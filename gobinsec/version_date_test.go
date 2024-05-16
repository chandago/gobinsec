package gobinsec

import (
	"testing"
	"time"
)

func TestNewDateVersion(t *testing.T) {
	version, err := NewDateVersion("2021-12-08")
	if err != nil {
		t.Fatalf("error parsing version: %v", err)
	}
	t1 := version.Date
	t2 := time.Date(2021, 12, 8, 0, 0, 0, 0, time.Now().UTC().Location())
	if !t1.Equal(t2) {
		t.Fatalf("creating date: %v", t1)
	}
}

func TestNewDateVersionErrors(t *testing.T) {
	_, err := NewDateVersion("xxx")
	if err == nil {
		t.Fatalf("should have failed parsing date")
	}
	if err.Error() != `parsing date version: parsing time "xxx" as "2006-01-02": cannot parse "xxx" as "2006"` {
		t.Fatalf("bad error message: %s", err.Error())
	}
}

func TestDateVersionString(t *testing.T) {
	version, err := NewDateVersion("2021-12-08")
	if err != nil {
		t.Fatalf("error parsing version: %v", err)
	}
	if version.String() != "2021-12-08" {
		t.Fatalf("bad string representation: %s", version.String())
	}
}

func TestDateVersionCompare(t *testing.T) {
	v1, _ := NewDateVersion("2021-12-08")
	v2, _ := NewDateVersion("2021-12-09")
	r, err := v1.Compare(v2)
	if err != nil {
		t.Fatalf("error comparing date versions: %v", err)
	}
	if r >= 0 {
		t.Fatalf("bad date comparison: %d", r)
	}
	v2, _ = NewDateVersion("2021-12-07")
	r, err = v1.Compare(v2)
	if err != nil {
		t.Fatalf("error comparing date versions: %v", err)
	}
	if r <= 0 {
		t.Fatalf("bad date comparison: %d", r)
	}
	v2, _ = NewDateVersion("2021-12-08")
	r, err = v1.Compare(v2)
	if err != nil {
		t.Fatalf("error comparing date versions: %v", err)
	}
	if r != 0 {
		t.Fatalf("bad date comparison: %d", r)
	}
}
