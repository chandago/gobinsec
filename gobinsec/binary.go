package gobinsec

import (
	"debug/buildinfo"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// NumGoroutines to load vulnerabilities
var NumGoroutines = 4 * runtime.NumCPU()

// Binary represents a binary with its dependencies
type Binary struct {
	Path         string        // path to binary file
	Dependencies []*Dependency // list of dependencies
	Vulnerable   bool          // tells if binary is vulnerable
	Config       *Config       // configuration
}

// NewBinary returns a binary
func NewBinary(path string, cfg *Config) (*Binary, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	binary := Binary{
		Path:   path,
		Config: cfg,
	}
	if err := binary.GetDependencies(); err != nil {
		return nil, err
	}
	return &binary, nil
}

// GetDependencies gets dependencies analyzing binary with buildinfo
func (b *Binary) GetDependencies() error {
	info, err := buildinfo.ReadFile(b.Path)
	if err != nil {
		return err
	}
	for _, dep := range info.Deps {
		for dep.Replace != nil {
			dep = dep.Replace
		}
		b.Dependencies = append(b.Dependencies, NewDependency(dep.Path, dep.Version, b.Config))
	}
	numGoroutines := NumGoroutines
	if b.Config.Wait {
		numGoroutines = 1
	}
	dependencies := make(chan *Dependency, len(b.Dependencies))
	for _, dependency := range b.Dependencies {
		dependencies <- dependency
	}
	close(dependencies)
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	errCh := make(chan error, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			if err := LoadVulnerabilities(dependencies); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if err, ok := <-errCh; ok {
		return err
	}
	for _, dependency := range b.Dependencies {
		if dependency.Vulnerable {
			b.Vulnerable = true
		}
	}
	return nil
}

// LoadVulnerabilities takes dependencies from channel and loads dependencies for it
func LoadVulnerabilities(dependencies chan *Dependency) error {
	for dependency := range dependencies {
		if err := dependency.LoadVulnerabilities(); err != nil {
			return fmt.Errorf("loading vulnerability: %w", err)
		}
	}
	return nil
}

// Report prints a report on terminal
func (b *Binary) Report() {
	fmt.Printf("%s: ", filepath.Base(b.Path))
	if b.Vulnerable {
		_, _ = ColorRed.Println("VULNERABLE")
	} else {
		_, _ = ColorGreen.Println("OK")
	}
	if len(b.Dependencies) > 0 && (b.Vulnerable || b.Config.Verbose) {
		fmt.Println("dependencies:")
		for _, dependency := range b.Dependencies {
			if !dependency.Vulnerable && !b.Config.Verbose {
				continue
			}
			fmt.Printf("- name:    '%s'\n", dependency.Name)
			fmt.Printf("  version: '%s'\n", dependency.Version)
			fmt.Printf("  vulnerable: %t\n", dependency.Vulnerable)
			if len(dependency.Vulnerabilities) > 0 {
				fmt.Println("  vulnerabilities:")
				for _, vulnerability := range dependency.Vulnerabilities {
					if !vulnerability.Exposed && !b.Config.Verbose {
						continue
					}
					fmt.Printf("  - id: '%s'\n", vulnerability.ID)
					fmt.Printf("    exposed: %t\n", vulnerability.Exposed)
					fmt.Printf("    ignored: %t\n", vulnerability.Ignored)
					fmt.Println("    references:")
					for _, reference := range vulnerability.References {
						fmt.Printf("    - '%s'\n", reference)
					}
					fmt.Println("    matches:")
					for _, match := range vulnerability.Matches {
						var text string
						if match.VersionStartExcluding != nil ||
							match.VersionStartIncluding != nil ||
							match.VersionEndExcluding != nil ||
							match.VersionEndIncluding != nil {
							var parts []string
							if match.VersionStartExcluding != nil {
								parts = append(parts, fmt.Sprintf("%v <", match.VersionStartExcluding))
							}
							if match.VersionStartIncluding != nil {
								parts = append(parts, fmt.Sprintf("%v <=", match.VersionStartIncluding))
							}
							parts = append(parts, "v")
							if match.VersionEndExcluding != nil {
								parts = append(parts, fmt.Sprintf("< %v", match.VersionEndExcluding))
							}
							if match.VersionEndIncluding != nil {
								parts = append(parts, fmt.Sprintf("<= %v", match.VersionEndIncluding))
							}
							text = strings.Join(parts, " ")
						} else {
							text = "?"
						}
						fmt.Printf("    - '%s'\n", text)
					}
				}
			}
		}
	}
}
