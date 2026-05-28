package gobinsec

import (
	"fmt"
	"strings"
	"time"
)

// PseudoVersionTimeFormat is the time format for pseudo versions (YYYYMMDD).
const PseudoVersionTimeFormat = "20060102"

// PseudoVersionTimestampLength is the length of the embedded YYYYMMDDhhmmss component.
const PseudoVersionTimestampLength = 14

// PseudoVersion for dependencies that don't have a version. Its string
// representation matches Go's pseudo-version forms, whose two last
// "-"-separated parts are always YYYYMMDDhhmmss and a short commit hash, e.g.:
//
//	v0.0.0-20191109021931-daa7c04131f5
//	v1.2.3-pre.0.20191109021931-daa7c04131f5
//	v1.2.4-0.20191109021931-daa7c04131f5
type PseudoVersion struct {
	Text string
	Date time.Time
}

// NewPseudoVersion builds a pseudo version from string. The penultimate
// "-"-separated part always ENDS with the 14-char YYYYMMDDhhmmss timestamp,
// possibly prefixed by a "0." or "pre.0." chunk depending on the pseudo-version
// form. We extract the last PseudoVersionTimestampLength chars and parse the
// first 8 (YYYYMMDD).
func NewPseudoVersion(text string) (*PseudoVersion, error) {
	parts := strings.Split(text, "-")
	if len(parts) < 3 {
		return nil, fmt.Errorf("wrong pseudo version format: %s", text)
	}
	mid := parts[len(parts)-2]
	if len(mid) < PseudoVersionTimestampLength {
		return nil, fmt.Errorf("wrong pseudo version timestamp: %s", text)
	}
	timestamp := mid[len(mid)-PseudoVersionTimestampLength:]
	date, err := time.Parse(PseudoVersionTimeFormat, timestamp[:len(PseudoVersionTimeFormat)])
	if err != nil {
		return nil, fmt.Errorf("wrong pseudo version time: %s", text)
	}
	return &PseudoVersion{Text: text, Date: date}, nil
}

// String returns a string representation for pseudo version
func (version *PseudoVersion) String() string {
	return version.Text
}

// Compare two pseudo versions by time
func (version *PseudoVersion) Compare(o interface{}) (int, error) {
	t, err := GetVersionTime(o)
	if err != nil {
		return 0, err
	}
	d := version.Date
	if d.Before(*t) {
		return -1, nil
	}
	if d.After(*t) {
		return 1, nil
	}
	return 0, nil
}
