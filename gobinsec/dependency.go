package gobinsec

// NVD API rate limit are specified in the following link:
// https://nvd.nist.gov/developers/start-here

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"
)

const (
	URL                  = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch="
	StatusCodeLimit      = 300
	WaitStringWithoutKey = "7s"
	WaitStringWithKey    = "0.7s"
)

// Dependency is a dependency with vulnerabilities
type Dependency struct {
	Name            string
	Version         Version
	Vulnerabilities []Vulnerability
	Vulnerable      bool
}

// timeLastCall is time for last NVD API call
var timeLastCall time.Time

// WaitWithoutKey is the time to wait between NVD API calls without API key
var WaitWithoutKey time.Duration

// WaitWithKey is the time to wait between NVD API calls with API key
var WaitWithKey time.Duration

func init() {
	WaitWithoutKey, _ = time.ParseDuration(WaitStringWithoutKey)
	WaitWithKey, _ = time.ParseDuration(WaitStringWithKey)
}

// NewDependency builds a new dependency and loads its vulnerabilities
func NewDependency(name, version string) (*Dependency, error) {
	v := NewVersion(version)
	dependency := Dependency{
		Name:    name,
		Version: v,
	}
	return &dependency, nil
}

// Vulnerabilities return list of vulnerabilities for given dependency
func (d *Dependency) LoadVulnerabilities() error {
	vulnerabilities, err := CacheInstance.Get(d)
	if err != nil {
		return err
	}
	if vulnerabilities == nil {
		WaitBeforeCall()
		url := URL + d.Name
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return fmt.Errorf("creating NVD request: %v", err)
		}
		if config.APIKey != "" {
			request.Header.Set("apiKey", config.APIKey)
		}
		response, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("calling NVD: %v", err)
		}
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode >= StatusCodeLimit {
			return fmt.Errorf("bad status code calling NVD: %d", response.StatusCode)
		}
		vulnerabilities, err = io.ReadAll(response.Body)
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
		vulnerability, err := NewVulnerability(item.CVE)
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

// WaitBeforeCall waits in order not to exceed NVD call rate limit
func WaitBeforeCall() {
	if config.Wait {
		elapsedSinceLastCall := time.Since(timeLastCall)
		timeToSleep := WaitWithoutKey
		if config.APIKey != "" {
			timeToSleep = WaitWithKey
		}
		timeToWait := timeToSleep - elapsedSinceLastCall
		if timeToWait > 0 {
			time.Sleep(timeToWait)
		}
		timeLastCall = time.Now()
	}
}

// Key returns a key as a string for caching
func (d *Dependency) Key() string {
	return d.Name
}
