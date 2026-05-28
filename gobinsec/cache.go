package gobinsec

import "fmt"

var CacheInstance Cache

// Cache is the interface for caching
type Cache interface {
	Name() string
	Get(d *Dependency) ([]byte, error)
	Set(d *Dependency, v []byte) error
	Open() error
	Close() error
}

// NewCache builds a cache instance depending on configuration and environment
func NewCache(cfg *Config) error {
	var err error
	CacheInstance, err = NewMemcachierCache(cfg.Memcachier)
	if err != nil {
		return fmt.Errorf("configuring memcachier: %v", err)
	}
	if CacheInstance != nil {
		return nil
	}
	CacheInstance, err = NewMemcachedCache(cfg.Memcached)
	if err != nil {
		return fmt.Errorf("configuring memcached: %v", err)
	}
	if CacheInstance != nil {
		return nil
	}
	CacheInstance, err = NewFileCache(cfg.File)
	if err != nil {
		return fmt.Errorf("configuring file cache: %v", err)
	}
	return nil
}

// BuildCache and open it
func BuildCache(cfg *Config) error {
	if err := NewCache(cfg); err != nil {
		return err
	}
	if cfg.Cache {
		CacheInstance = NewCacheLogger(CacheInstance)
	}
	return CacheInstance.Open()
}
