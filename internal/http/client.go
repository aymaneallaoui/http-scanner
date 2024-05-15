package http

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aymaneallaoui/go-http-scanner/internal/model"
)

const (
	UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
)

type Client struct {
	httpClient *http.Client
	timeout    int
	maxRetries int
	transport  *http.Transport
}

func NewClient(timeout, maxRetries int, followRedirects, skipSSLVerify bool) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: skipSSLVerify,
		},
		DisableKeepAlives:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   time.Duration(timeout) * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	if !followRedirects {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		}
	}

	return &Client{
		httpClient: httpClient,
		timeout:    timeout,
		maxRetries: maxRetries,
		transport:  transport,
	}, nil
}

func (c *Client) SendRequest(target model.Target, method, path string, headers map[string]string, body io.Reader) (*http.Response, error) {
	urlPath := target.URL
	if path != "" && !strings.HasPrefix(path, "http") {
		if !strings.HasSuffix(target.URL, "/") && !strings.HasPrefix(path, "/") {
			urlPath = target.URL + "/" + path
		} else {
			urlPath = target.URL + path
		}
	} else if path != "" {
		urlPath = path
	}

	req, err := http.NewRequest(method, urlPath, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "close")

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	var resp *http.Response
	var reqErr error

	for attempt := 0; attempt < c.maxRetries; attempt++ {
		resp, reqErr = c.httpClient.Do(req)
		if reqErr == nil {
			break
		}

		if attempt < c.maxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	if reqErr != nil {
		return nil, fmt.Errorf("request failed after %d attempts: %v", c.maxRetries, reqErr)
	}

	return resp, nil
}

func (c *Client) SendRawRequest(target model.Target, payload string) (string, error) {
	timeout := time.Duration(c.timeout) * time.Second

	var conn net.Conn
	var err error

	address := fmt.Sprintf("%s:%s", target.Hostname, target.Port)

	var connectErr error
	for attempt := 0; attempt < c.maxRetries; attempt++ {
		if target.SSL {
			dialer := &net.Dialer{Timeout: timeout}
			tlsConfig := &tls.Config{
				InsecureSkipVerify: c.transport.TLSClientConfig.InsecureSkipVerify,
			}
			conn, connectErr = tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
		} else {
			conn, connectErr = net.DialTimeout("tcp", address, timeout)
		}

		if connectErr == nil {
			break
		}

		if attempt < c.maxRetries-1 {
			time.Sleep(time.Duration(attempt+1) * 500 * time.Millisecond)
		}
	}

	if connectErr != nil {
		return "", fmt.Errorf("failed to connect after %d attempts: %v", c.maxRetries, connectErr)
	}

	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	_, err = fmt.Fprintf(conn, payload)
	if err != nil {
		return "", err
	}

	reader := bufio.NewReader(conn)
	var response strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return response.String(), nil
		}
		response.WriteString(line)
	}

	return response.String(), nil
}
