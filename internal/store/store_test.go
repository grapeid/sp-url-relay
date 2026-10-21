package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestAnUnprovedDomainRequestLapses(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	s.now = func() time.Time { return now }
	if err := s.RequestDomain("x.example.org", "EOLD", 3, 7*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.RequestDomain("x.example.org", "ENEW", 3, 7*24*time.Hour); !errors.Is(err, ErrTaken) {
		t.Fatalf("a fresh request by another identity: %v, want ErrTaken", err)
	}
	now = now.Add(8 * 24 * time.Hour)
	if err := s.RequestDomain("x.example.org", "ENEW", 3, 7*24*time.Hour); err != nil {
		t.Fatalf("a request never proved for a week still blocks the domain: %v", err)
	}
}
