package gobinsec

// NVD API rate limit are specified in the following link:
// https://nvd.nist.gov/developers/start-here

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

const (
	URL                   = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
	StatusCodeLimit       = 300
	WaitStringWithoutKey  = "7s"
	WaitStringWithKey     = "0.7s"
	WaitOnTooManyAttempts = 30 * time.Second
	HTTPRequestTimeout    = 30 * time.Second
	MaxAttempts           = 3
)

// Dependency is a dependency with vulnerabilities
type Dependency struct {
	Name            string
	Version         Version
	Vulnerabilities []Vulnerability
	Vulnerable      bool
	Config          *Config
}

// WaitWithoutKey is the time to wait between NVD API calls without API key
var WaitWithoutKey time.Duration

// WaitWithKey is the time to wait between NVD API calls with API key
var WaitWithKey time.Duration

func init() {
	WaitWithoutKey, _ = time.ParseDuration(WaitStringWithoutKey)
	WaitWithKey, _ = time.ParseDuration(WaitStringWithKey)
}

// NewDependency builds a new dependency
func NewDependency(name, version string, cfg *Config) *Dependency {
	return &Dependency{
		Name:    name,
		Version: NewVersion(version),
		Config:  cfg,
	}
}

// Vulnerabilities return list of vulnerabilities for given dependency
func (d *Dependency) LoadVulnerabilities(ctx context.Context) error {
	vulnerabilities, err := CacheInstance.Get(d)
	if err != nil {
		return err
	}
	if vulnerabilities == nil {
		if err := d.waitBeforeCall(ctx); err != nil {
			return err
		}
		vulnerabilities, err = d.fetchVulnerabilities(ctx, 0)
		if err != nil {
			return err
		}
		if err := CacheInstance.Set(d, vulnerabilities); err != nil {
			return err
		}
	}
	var result Result
	if err := json.Unmarshal(vulnerabilities, &result); err != nil {
		return fmt.Errorf("decoding JSON response: %v", err)
	}
	for _, item := range result.Vulnerabilities {
		vulnerability, err := NewVulnerability(item.CVE, d.Config)
		if err != nil {
			return err
		}
		if vulnerability.IsExposed(d.Version) &&
			!vulnerability.Ignored {
			d.Vulnerable = true
		}
		d.Vulnerabilities = append(d.Vulnerabilities, *vulnerability)
	}
	sort.Slice(d.Vulnerabilities, func(i, j int) bool {
		return d.Vulnerabilities[i].ID < d.Vulnerabilities[j].ID
	})
	return nil
}

// waitBeforeCall waits in order not to exceed NVD call rate limit.
// Returns ctx.Err() if the context is cancelled during the sleep.
func (d *Dependency) waitBeforeCall(ctx context.Context) error {
	if !d.Config.Wait {
		return nil
	}
	delay := WaitWithoutKey
	if d.Config.APIKey != "" {
		delay = WaitWithKey
	}
	return sleepCtx(ctx, delay)
}

// sleepCtx sleeps for the given duration, returning early with ctx.Err()
// if the context is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Key returns a key as a string for caching
func (d *Dependency) Key() string {
	return d.Name
}

func (d *Dependency) fetchVulnerabilities(ctx context.Context, attempt int) ([]byte, error) {
	client := &http.Client{Timeout: HTTPRequestTimeout}
	request, err := http.NewRequestWithContext(ctx, "GET", URL+d.Name, nil)
	if err != nil {
		return nil, fmt.Errorf("creating NVD request: %v", err)
	}
	if d.Config.APIKey != "" {
		request.Header.Set("apiKey", d.Config.APIKey)
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("calling NVD: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= StatusCodeLimit {
		if response.StatusCode == http.StatusTooManyRequests {
			if attempt < MaxAttempts {
				if err := sleepCtx(ctx, WaitOnTooManyAttempts); err != nil {
					return nil, err
				}
				return d.fetchVulnerabilities(ctx, attempt+1)
			}
		}
		return nil, fmt.Errorf("bad status code calling NVD: %d", response.StatusCode)
	}
	vulnerabilities, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return vulnerabilities, nil
}
