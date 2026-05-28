package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/chandago/gobinsec/gobinsec"
)

const (
	CodeVulnerable = 1
	CodeError      = 2
)

var Version = "NONE"

func main() {
	version := flag.Bool("version", false, "Print gobinsec version")
	verbose := flag.Bool("verbose", false, "Print additional information in terminal")
	cache := flag.Bool("cache", false, "Print cache information in terminal")
	wait := flag.Bool("wait", false, "Wait between NVD API calls")
	strict := flag.Bool("strict", false, "Vulnerabilities without version are exposed")
	config := flag.String("config", "", "Configuration file")
	flag.Parse()
	if *version {
		fmt.Println(Version)
		os.Exit(0)
	}
	if len(flag.Args()) < 1 {
		fmt.Fprintln(os.Stderr, "ERROR you must pass binary/ies to analyze on command line")
		os.Exit(CodeError)
	}
	configuration, err := gobinsec.LoadConfig(*config, *strict, *wait, *verbose, *cache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR %v\n", err)
		os.Exit(CodeError)
	}
	if err := gobinsec.BuildCache(configuration); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR building cache: %v\n", err)
		os.Exit(CodeError)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	vulnerable := false
	analysisError := false
	for _, path := range flag.Args() {
		binary, err := gobinsec.NewBinary(ctx, path, configuration)
		if err != nil {
			_, _ = gobinsec.ColorRed.Print("ERROR")
			fmt.Printf(" analyzing %s: %v\n", path, err)
			analysisError = true
		} else {
			binary.Report()
			if binary.Vulnerable {
				vulnerable = true
			}
		}
	}
	if err := gobinsec.CacheInstance.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR closing cache: %v\n", err)
		os.Exit(CodeError)
	}
	if analysisError {
		os.Exit(CodeError)
	}
	if vulnerable {
		os.Exit(CodeVulnerable)
	}
}
