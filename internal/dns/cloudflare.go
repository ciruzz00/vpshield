// Package dns manages Cloudflare DNS records and the local resolver.
package dns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const cfAPI = "https://api.cloudflare.com/client/v4"

// TokenFile is the secret file name inside /etc/vpshield.
const TokenFile = "cloudflare.token"

type Client struct {
	Token string
	HTTP  *http.Client
}

func NewClient(token string) *Client {
	return &Client{Token: token, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Record struct {
	ID       string         `json:"id,omitempty"`
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Content  string         `json:"content,omitempty"`
	TTL      int            `json:"ttl"`
	Proxied  *bool          `json:"proxied,omitempty"`
	Priority *int           `json:"priority,omitempty"`
	Comment  string         `json:"comment,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type cfError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	Success bool            `json:"success"`
	Errors  []cfError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

func (c *Client) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cfAPI+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success {
		var msgs []string
		for _, e := range env.Errors {
			msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
		}
		return fmt.Errorf("cloudflare: %s", strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// Verify checks the token is valid and active.
func (c *Client) Verify() error {
	var r struct {
		Status string `json:"status"`
	}
	if err := c.do("GET", "/user/tokens/verify", nil, &r); err != nil {
		return err
	}
	if r.Status != "active" {
		return fmt.Errorf("token status: %s", r.Status)
	}
	return nil
}

func (c *Client) Zones() ([]Zone, error) {
	var z []Zone
	err := c.do("GET", "/zones?per_page=50", nil, &z)
	return z, err
}

func (c *Client) Records(zoneID string) ([]Record, error) {
	var all []Record
	for page := 1; page <= 20; page++ {
		var rs []Record
		q := url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}
		if err := c.do("GET", "/zones/"+zoneID+"/dns_records?"+q.Encode(), nil, &rs); err != nil {
			return nil, err
		}
		all = append(all, rs...)
		if len(rs) < 100 {
			break
		}
	}
	return all, nil
}

func (c *Client) Create(zoneID string, r Record) (Record, error) {
	var out Record
	err := c.do("POST", "/zones/"+zoneID+"/dns_records", r, &out)
	return out, err
}

func (c *Client) Update(zoneID string, r Record) (Record, error) {
	var out Record
	err := c.do("PUT", "/zones/"+zoneID+"/dns_records/"+r.ID, r, &out)
	return out, err
}

func (c *Client) Delete(zoneID, recordID string) error {
	return c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil, nil)
}

// Upsert creates the record or updates the first one with same type+name.
func (c *Client) Upsert(zoneID string, r Record) (Record, bool, error) {
	existing, err := c.Records(zoneID)
	if err != nil {
		return Record{}, false, err
	}
	for _, e := range existing {
		if strings.EqualFold(e.Type, r.Type) && strings.EqualFold(e.Name, r.Name) && r.Type != "TXT" && r.Type != "MX" {
			r.ID = e.ID
			out, err := c.Update(zoneID, r)
			return out, true, err
		}
	}
	out, err := c.Create(zoneID, r)
	return out, false, err
}

// PublicIP asks Cloudflare's trace endpoint which address we come from.
func PublicIP(v6 bool) (string, error) {
	host := "https://1.1.1.1/cdn-cgi/trace"
	if v6 {
		host = "https://[2606:4700:4700::1111]/cdn-cgi/trace"
	}
	cl := &http.Client{Timeout: 6 * time.Second}
	resp, err := cl.Get(host)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "ip="); ok {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("no ip in trace response")
}

// FQDN turns "@" or "www" into a full name inside zone.
func FQDN(name, zone string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	switch {
	case name == "" || name == "@":
		return zone
	case name == zone || strings.HasSuffix(name, "."+zone):
		return name
	}
	return name + "." + zone
}

// ValidateContent does basic per-type checks before calling the API.
func ValidateContent(typ, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return fmt.Errorf("content is required")
	}
	switch typ {
	case "A":
		if ip := net.ParseIP(content); ip == nil || ip.To4() == nil {
			return fmt.Errorf("not an IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(content); ip == nil || ip.To4() != nil {
			return fmt.Errorf("not an IPv6 address")
		}
	case "CNAME", "MX", "NS":
		if strings.ContainsAny(content, " /") {
			return fmt.Errorf("must be a hostname")
		}
	}
	return nil
}

var RecordTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "CAA", "SRV", "NS"}

// Proxiable reports whether the orange cloud can be turned on.
func Proxiable(typ string) bool { return typ == "A" || typ == "AAAA" || typ == "CNAME" }

func BoolPtr(b bool) *bool { return &b }
func IntPtr(i int) *int    { return &i }
