# Gobinsec

This tool parses Go binary dependencies, calls NVD database to produce a vulnerability report for this binary.

## Install

Download binary for your platform in [latest release](https://github.com/intercloud/gobinsec/releases). Rename it *gobinsec*, make it executable with `chmod +x gobinsec` and move it somewhere in your *PATH*.

## Usage

To analyze given binary:

```yaml
$ gobinsec path/to/binary
binary: 'binary'
vulnerable: true
dependencies:
- name:    'golang.org/x/text'
  version: 'v0.3.0'
  vulnerable: true
  vulnerabilities:
  - id: 'CVE-2020-14040'
    exposed: true
    ignored: false
    references:
    - 'https://groups.google.com/forum/#!topic/golang-announce/bXVeAmGOqz0'
    - 'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/TACQFZDPA7AUR6TRZBCX2RGRFSDYLI7O/'
    matchs:
    - 'v < 0.3.3'
    - '?'
```

Exit code is *1* if binary is vulnerable, *2* if there was an error analyzing binary and *0* otherwise. If binary is vulnerable, exposed vulnerabilities are printed in report.

You can pass *-verbose* option on command line to print vulnerability report, even if binary is not vulnerable and for all vulnerabilities, even if they are ignored or not exposed.

You can set *-strict* flag on command line so that vulnerabilities without version are considered matching vulnerability. In this case, you should check vulnerability manually and disable it in configuration file if necessary.

## Configuration

You can pass configuration on command line with `-config` option:

```
$ gobinsec -config config.yml path/to/binary
```

Configuration file is in YAML format as follows:

```yaml
api-key: "28c6112c-a7bc-4a4e-9b14-75be6da02211"
strict: false
ignore:
- "CVE-2020-14040"
```

It has two entries:

- **api-key**: this is your NVD API key
- **strict**: tells if we should consider vulnerability matches without version as matching dependency
- **ignore**: a list of CVE vulnerabilities to ignore

You can also set NVD API Key in your environment with variable *NVD_API_KEY*. This key may be overwritten with value in configuration file. Your API key must be set in environment to be able to run integration tests (with target *integ*).

Note that without API key, you will be limited to *10* requests in a rolling *60* second window while this limit is *100* with an API key.

## Versions

Dependencies and vulnerabilities have versions. There are three types of them:

- **Tag**: which implements semantic versioning, such as `1.2.3` or `v1.2.3`
- **Commit**: such as `v0.0.0-20210410081132-afb366fc7cd1` which is made of three parts: a major version, build date and commit ID
- **Date**: in ISO format such as `2022-01-07`

A dependency may have a tag or commit version. In the first case, developer used a released version of this dependency, in the last he's using a particular commit that wasn't released.

A vulnerability might have version conditions on tag or date. For instance:

- `v < 2017-03-17` means that vulnerability will affect dependencies before *2017-03-17*.
- `1.16.0 <= v <= 1.16.4` means that vulnerability will affect dependencies from version *1.16.0* to *1.16.4*, included

Given vulnerability is exposed if dependency version is in the range of affected versions. Thus to determine if a dependency is affected we must be able to compare versions between dependency and vulnerability.

- This is possible if dependency has a commit version and vulnerability a date one
- This is possible if dependency has a tag version and vulnerability a tag one
- This is not possible if dependency has a tag version and vulnerability a date one

In this later case, the vulnerability is considered exposed. You should check manually if release date of the dependency is in the date range of the vulnerability or not. You can then ignore vulnerability adding its ID in the configuration *ignore* list.

Sometimes, vulnerabilities have no version or date range. This is the case when vulnerability affects a given software (a Linux distribution for instance). In this case, vulnerability condition appears as a question mark and we consider that dependency is not affected. You can change this behavior passing `-strict` option on command line or in configuration. In this case you will have to check manually and ignore such vulnerabilities.

## Data source

This tool first lists dependencies embedded in binary with `go version -m binary` command:

```
$ go version -m test/binary
test/binary: go1.17.3
	path	nancy-test
	mod	nancy-test	(devel)
	dep	golang.org/x/text	v0.3.0	h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=
```

Then, it calls [National Vulnerability Database](https://nvd.nist.gov/) to lists known vulnerabilities for embedded dependencies. You can find documentation on its API at <https://nvd.nist.gov/developers/vulnerabilities> and get an API key here: <https://nvd.nist.gov/developers/request-an-api-key>.

For instance, to get vulnerabilities for library *golang.org/x/text*, we would call <https://services.nvd.nist.gov/rest/json/cves/1.0/?keyword=golang.org/x/text>, which returns following JSON payload:

```json
{
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "result": {
        "CVE_data_type": "CVE",
        "CVE_data_format": "MITRE",
        "CVE_data_version": "4.0",
        "CVE_data_timestamp": "2021-12-07T15:40Z",
        "CVE_Items": [
            {
                "cve": {
                    "data_type": "CVE",
                    "data_format": "MITRE",
                    "data_version": "4.0",
                    "CVE_data_meta": {
                        "ID": "CVE-2020-14040",
                        "ASSIGNER": "cve@mitre.org"
                    },
                    "problemtype": {
                        ...
                    },
                    "references": {
                        "reference_data": [
                            {
                                "url": "https://groups.google.com/forum/#!topic/golang-announce/bXVeAmGOqz0",
                                "name": "https://groups.google.com/forum/#!topic/golang-announce/bXVeAmGOqz0",
                                "refsource": "MISC",
                                "tags": [
                                    "Third Party Advisory"
                                ]
                            },
                            ...
                        ]
                    },
                    "description": {
                        "description_data": [
                            {
                                "lang": "en",
                                "value": "..."
                            }
                        ]
                    }
                },
                "configurations": {
                    "CVE_data_version": "4.0",
                    "nodes": [
                        {
                            "operator": "OR",
                            "children": [],
                            "cpe_match": [
                                {
                                    "vulnerable": true,
                                    "cpe23Uri": "cpe:2.3:a:golang:text:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "0.3.3",
                                    "cpe_name": []
                                }
                            ]
                        },
                        ...
                    ]
                },
                "impact": {
                    "baseMetricV3": {
                        ...
                    },
                    "baseMetricV2": {
                        ...
                    }
                },
                "publishedDate": "2020-06-17T20:15Z",
                "lastModifiedDate": "2020-11-18T14:44Z"
            }
        ]
    }
}
```

This data is parsed to produce YAML report.

*Enjoy!*
