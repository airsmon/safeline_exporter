package safeline

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxResponseSize = 16 << 20

type Options struct {
	Address            string
	Token              string
	Timeout            time.Duration
	InsecureSkipVerify bool
	AllowHTTP          bool
	UserAgent          string
}

type Client struct {
	baseURL   *url.URL
	token     string
	userAgent string
	http      *http.Client
}

func NewClient(options Options) (*Client, error) {
	baseURL, err := url.Parse(strings.TrimRight(options.Address, "/"))
	if err != nil || baseURL.Host == "" || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return nil, fmt.Errorf("invalid SafeLine address %q", options.Address)
	}
	if baseURL.Scheme == "http" && !options.AllowHTTP {
		return nil, errors.New("plain HTTP SafeLine address requires safeline.allow-http")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: options.InsecureSkipVerify} //nolint:gosec -- explicit operator option
	return &Client{
		baseURL:   baseURL,
		token:     options.Token,
		userAgent: options.UserAgent,
		http: &http.Client{
			Timeout:   options.Timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *Client) Get(ctx context.Context, path string, query url.Values, target any) error {
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + path
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-SLCE-API-TOKEN", c.token)
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s returned HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}
