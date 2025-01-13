module github.com/intercloud/gobinsec

go 1.18

require (
	github.com/bradfitz/gomemcache v0.0.0-20230905024940-24af94b03874
	github.com/fatih/color v1.17.0
	github.com/memcachier/gomemcache v0.0.0-20170425125614-d027381f7653
	gopkg.in/yaml.v3 v3.0.1
)

replace github.com/intercloud/gobinsec => github.com/chandago/gobinsec v1.1.0

require (
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/sys v0.20.0 // indirect
)
