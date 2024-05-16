package gobinsec

type Result struct {
	ResultsPerPage  int                `json:"resultsPerPage"`
	StartIndex      int                `json:"startIndex"`
	TotalResults    int                `json:"totalResults"`
	Vulnerabilities []CVEVulnerability `json:"vulnerabilities"`
}

type CVEVulnerability struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID             string          `json:"id"`
	Descriptions   []Description   `json:"descriptions"`
	Configurations []Configuration `json:"configurations"`
	References     []Reference     `json:"references"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Configuration struct {
	Nodes []Node `json:"nodes"`
}

type Node struct {
	Operator string  `json:"operator"`
	Negate   bool    `json:"negate"`
	Match    []Match `json:"cpeMatch"`
}

type Reference struct {
	URL string `json:"url"`
}

type Match struct {
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}
