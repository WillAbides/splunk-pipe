package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/jmespath/go-jmespath"
)

var kongVars = kong.Vars{
	"header_help":         `Header to sent with the request in the same format as curl. e.g. '-H "Authorization: Splunk $HEC_KEY"'`,
	"batch_size_help":     `Number of events to send in a batch.`,
	"flush_interval_help": `Time in milliseconds to wait before sending a partial batch. Set to 0 to never send a partial batch.`,
	"endpoint_help":       `Endpoint for posting events`,

	"index_help":      `Value for the "index" field. JMESPath expressions allowed with "jp:" prefix.`,
	"host_help":       `Value for the "host" field. JMESPath expressions allowed with "jp:" prefix.`,
	"sourcetype_help": `Value for the "sourcetype" field. JMESPath expressions allowed with "jp:" prefix.`,
	"source_help":     `Value for the "source" field. JMESPath expressions allowed with "jp:" prefix.`,
	"time_help":       `Value for the "eventTime" field converted from epoch milliseconds. JMESPath expressions allowed with "jp:" prefix.`,
}

type cliOptions struct {
	Endpoint      string   `kong:"arg,required,help=${endpoint_help}"`
	Sourcetype    string   `kong:"short=t,name='sourcetype',help=${sourcetype_help}"`
	Source        string   `kong:"short=s,name='source',help=${source_help}"`
	Time          string   `kong:"name='timestamp',short=T,help=${time_help}"`
	Header        []string `kong:"short=H,help=${header_help}"`
	Host          string   `kong:"short=h,help=${host_help}"`
	Index         string   `kong:"help=${index_help}"`
	BatchSize     int      `kong:"default=10,help=${batch_size_help}"`
	FlushInterval int      `kong:"default=2000,help=${flush_interval_help}"`

	jmespaths map[string]*jmespath.JMESPath
	optDefs   map[string]string
}

const helpDescription = `splunkpipe posts events to splunk.

example:
  $ splunk_endpoint="http://localhost:8080"
  $ splunk_hec_token="shhh_secret_token"
  $ data="$(cat <<"EOF"
      {"action": "obj.add", "@timestamp": 1604953432032, "el_name": "foo", "doc_id": "asdf"}
      {"action": "obj.rem", "@timestamp": 1604953732032, "el_name": "bar", "doc_id": "fdsa"}
    EOF
    )"
  $ echo "$data" | \
    splunkpipe "$splunk_endpoint" \
    -H "Authorization: Splunk $splunk_hec_token" \
    -T 'jp:"@timestamp"'

Learn about JMESPath syntax at https://jmespath.org
`

const jmespathPrefix = "jp:"

func main() {
	var cli cliOptions
	k := kong.Parse(&cli, kongVars, kong.Description(helpDescription))
	scanner := bufio.NewScanner(os.Stdin)
	ctx := context.Background()
	err := run(ctx, &cli, scanner)
	k.FatalIfErrorf(err)
}

type lineData struct {
	data  []byte
	iface interface{}
}

func (c *cliOptions) url() (string, error) {
	endpoint := c.Endpoint
	if !strings.Contains(endpoint, `://`) {
		endpoint = "https://" + endpoint
	}
	pURL, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}

	if pURL.Path == "" {
		pURL.Path = `services/collector/event`
	}

	return pURL.String(), nil
}

func (l lineData) unmarshalled() (interface{}, error) {
	if l.iface == nil {
		err := json.Unmarshal(l.data, &l.iface)
		if err != nil {
			return nil, err
		}
	}
	return l.iface, nil
}

func run(ctx context.Context, cli *cliOptions, scanner *bufio.Scanner) error {
	header := http.Header{}

	for _, hdr := range cli.Header {
		parts := strings.SplitN(hdr, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid header %q", hdr)
		}
		header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	thURL, err := cli.url()
	if err != nil {
		return err
	}
	publisher := &splunkPublisher{
		resetTicker:  func() {},
		maxQueueSize: cli.BatchSize,
		endpoint:     thURL,
		reqHeader:    header,
	}

	doneMutex := new(sync.Mutex)
	done := false
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		doneMutex.Lock()
		done = true
		doneMutex.Unlock()
	}()

	if cli.FlushInterval != 0 {
		interval := time.Duration(cli.FlushInterval) * time.Millisecond
		ticker := time.NewTicker(interval)
		publisher.resetTicker = func() {
			ticker.Reset(interval)
		}
		go func() {
			for range ticker.C {
				err2 := publisher.flushIfNeeded(ctx, 0)
				if err2 != nil {
					os.Exit(1)
				}
			}
		}()
	}

	for scanner.Scan() {
		b := scanner.Bytes()
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			continue
		}
		var ev *event
		ev, err = buildEvent(cli, scanner.Bytes())
		if err != nil {
			return err
		}
		err = publisher.addEvent(ctx, ev)
		if err != nil {
			return err
		}
		if done {
			break
		}
	}
	err = publisher.flushIfNeeded(ctx, 0)
	if err != nil {
		return err
	}
	return scanner.Err()
}

func (c *cliOptions) jmespath(name, val string) (*jmespath.JMESPath, error) {
	var err error
	if !strings.HasPrefix(val, jmespathPrefix) {
		return nil, nil
	}
	if c.jmespaths == nil {
		c.jmespaths = map[string]*jmespath.JMESPath{}
	}
	if c.jmespaths[name] == nil {
		c.jmespaths[name], err = jmespath.Compile(strings.TrimPrefix(val, jmespathPrefix))
		if err != nil {
			return nil, err
		}
	}
	return c.jmespaths[name], nil
}

func (c *cliOptions) optDef(name string) string {
	if c.optDefs == nil {
		c.optDefs = map[string]string{
			"source":     c.Source,
			"sourcetype": c.Sourcetype,
			"host":       c.Host,
			"index":      c.Index,
			"time":       c.Time,
		}
	}
	return c.optDefs[name]
}

func (c *cliOptions) getVal(valName string, data lineData) (string, error) {
	optDef := c.optDef(valName)

	if strings.HasPrefix(optDef, jmespathPrefix) {
		jp, err := c.jmespath(valName, optDef)
		if err != nil {
			return "", err
		}
		jd, err := data.unmarshalled()
		if err != nil {
			return "", err
		}
		return jmespathString(jp, jd)
	}
	return optDef, nil
}

func buildEvent(cli *cliOptions, data []byte) (*event, error) {
	ev := new(event)

	ld := lineData{
		data: data,
	}
	var err error
	ev.Index, err = cli.getVal("index", ld)
	if err != nil {
		return nil, err
	}

	ev.Host, err = cli.getVal("host", ld)
	if err != nil {
		return nil, err
	}

	ev.Sourcetype, err = cli.getVal("sourcetype", ld)
	if err != nil {
		return nil, err
	}

	ev.Source, err = cli.getVal("source", ld)
	if err != nil {
		return nil, err
	}

	ev.Time, err = cli.eventTime(ld)
	if err != nil {
		return nil, err
	}

	ev.Event = json.RawMessage(data)

	return ev, nil
}

func (c *cliOptions) eventTime(ld lineData) (float64, error) {
	strVal, err := c.getVal("time", ld)
	if err != nil {
		return 0, err
	}
	if strVal == "" {
		return 0, nil
	}
	iVal, err := strconv.ParseInt(strVal, 10, 64)
	if err != nil {
		return 0, err
	}
	secs := float64(iVal) / 1000
	return secs, nil
}

func jmespathString(jp *jmespath.JMESPath, data interface{}) (string, error) {
	got, err := jp.Search(data)
	if err != nil {
		return "", err
	}
	switch val := got.(type) {
	case string:
		return val, nil
	case float64:
		return fmt.Sprintf("%.0f", val), nil
	default:
		return fmt.Sprintf("%v", val), nil
	}
}

type splunkPublisher struct {
	mutex        sync.Mutex
	endpoint     string
	httpClient   *http.Client
	reqHeader    http.Header
	maxQueueSize int
	cache        []*event
	resetTicker  func()
}

func (p *splunkPublisher) addEvent(ctx context.Context, ev *event) error {
	p.mutex.Lock()
	p.cache = append(p.cache, ev)
	if len(p.cache) == 1 {
		p.resetTicker()
	}
	p.mutex.Unlock()
	return p.flushIfNeeded(ctx, p.maxQueueSize)
}

func (p *splunkPublisher) flushIfNeeded(ctx context.Context, maxQueueSize int) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if len(p.cache) == 0 || len(p.cache) < maxQueueSize {
		return nil
	}
	err := p.flush(ctx)
	if err != nil {
		return err
	}
	p.cache = p.cache[:0]
	return nil
}

func (p *splunkPublisher) flush(ctx context.Context) error {
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	var err error
	for _, ev := range p.cache {
		err = encoder.Encode(ev)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, &buf)
	if err != nil {
		return err
	}
	req.Header = p.reqHeader
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpClient := p.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		b, err := ioutil.ReadAll(resp.Body)
		_ = err
		fmt.Println(string(b))
		return fmt.Errorf("not OK, statusCode: %d", resp.StatusCode)
	}
	return nil
}

type event struct {
	Time       float64     `json:"time,omitempty"`
	Host       string      `json:"host,omitempty"`
	Source     string      `json:"source,omitempty"`
	Sourcetype string      `json:"sourcetype,omitempty"`
	Index      string      `json:"index,omitempty"`
	Event      interface{} `json:"event,omitempty"`
}
