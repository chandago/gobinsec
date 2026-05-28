package gobinsec

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the configuration from YAML config file and command line options
type Config struct {
	APIKey     string            `yaml:"api-key"`
	Memcached  *MemcachedConfig  `yaml:"memcached"`
	Memcachier *MemcachierConfig `yaml:"memcachier"`
	File       *FileConfig       `yaml:"file"`
	Ignore     []string          `yaml:"ignore"`
	Strict     bool              `yaml:"strict"`
	Verbose    bool              `yaml:"verbose"`
	Cache      bool              `yaml:"cache"`
	Wait       bool              `yaml:"wait"`
}

// LoadConfig loads configuration from given file and overwrite with command line options
func LoadConfig(path string, strict, wait, verbose, cache bool) (*Config, error) {
	var cfg Config
	if path != "" {
		bytes, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("loading configuration file: %v", err)
		}
		if err := yaml.Unmarshal(bytes, &cfg); err != nil {
			return nil, fmt.Errorf("parsing configuration: %v", err)
		}
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("NVD_API_KEY")
	}
	if strict {
		cfg.Strict = true
	}
	if wait {
		cfg.Wait = true
	}
	if verbose {
		cfg.Verbose = true
	}
	if cache {
		cfg.Cache = true
	}
	return &cfg, nil
}

// IgnoreVulnerability tells if we should ignore given vulnerability
func (c *Config) IgnoreVulnerability(id string) bool {
	for _, ignore := range c.Ignore {
		if ignore == id {
			return true
		}
	}
	return false
}
