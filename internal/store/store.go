// Package store keeps what a relay must remember across a restart, and
// nothing more.
//
// What it keeps, by mode:
//   - every mode: the key event log of each identifier it has admitted, so a
//     key rotated away from can never be admitted again (ADR-048 §3.5);
//   - private: each allocation's label and a commitment to the secret that
//     proves who made it. Never which identifier made it: the link between an
//     identity and its relationships lives only in memory, while that
//     identity is connected;
//   - public: claimed names and custom domains, and who holds them. A public
//     address is public, so its holder is too.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// Errors a caller tells apart.
var (
	ErrTaken    = errors.New("already held by another identity")
	ErrNotFound = errors.New("not found")
	ErrNotYours = errors.New("held by another identity")
)

// schemaVersion is stored in SQLite's user_version. Version 1 was the
// earlier frame protocol's schema, which linked every allocation to the
// enrolment that made it; it is dropped, not migrated.
const schemaVersion = 2

// Store is the relay's SQLite database.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	// One writer: SQLite serialises writes anyway, and one connection keeps
	// the read-check-write sequences below free of interleaving.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	if v == schemaVersion {
		return nil
	}
	stmts := []string{
		`DROP TABLE IF EXISTS allocations`,
		`DROP TABLE IF EXISTS enrollments`,
		`DROP TABLE IF EXISTS quarantine`,
		`CREATE TABLE IF NOT EXISTS key_logs (
			aid TEXT PRIMARY KEY,
			kel BLOB NOT NULL,
			updated_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS private_allocations (
			label TEXT PRIMARY KEY,
			commitment TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS names (
			name TEXT PRIMARY KEY,
			aid TEXT NOT NULL,
			claimed_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_names_aid ON names(aid)`,
		`CREATE TABLE IF NOT EXISTS released_names (
			name TEXT PRIMARY KEY,
			aid TEXT NOT NULL,
			released_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS domains (
			domain TEXT PRIMARY KEY,
			aid TEXT NOT NULL,
			verified INTEGER NOT NULL DEFAULT 0,
			requested_at TEXT NOT NULL,
			verified_at TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_domains_aid ON domains(aid)`,
		fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion),
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

func (s *Store) stamp() string { return s.now().UTC().Format(time.RFC3339) }

// KEL returns the key event log held for an identifier.
func (s *Store) KEL(aid string) ([]byte, bool, error) {
	var kel []byte
	err := s.db.QueryRow(`SELECT kel FROM key_logs WHERE aid = ?`, aid).Scan(&kel)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return kel, err == nil, err
}

// PutKEL records the key event log the identifier's current session holds.
// The caller is responsible for writing only a log that extends the one held:
// the relay writes a session's log only while that session is still the
// identifier's own, and the session registry admits only extending logs.
func (s *Store) PutKEL(aid string, kel []byte) error {
	_, err := s.db.Exec(`INSERT INTO key_logs (aid, kel, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(aid) DO UPDATE SET kel = excluded.kel, updated_at = excluded.updated_at`,
		aid, kel, s.stamp())
	return err
}

// CreateAllocation records a private allocation's label and the commitment to
// its owner's secret.
func (s *Store) CreateAllocation(label, commitment string) error {
	_, err := s.db.Exec(`INSERT INTO private_allocations (label, commitment, created_at) VALUES (?, ?, ?)`,
		label, commitment, s.stamp())
	return err
}

// Allocation returns a private allocation's commitment.
func (s *Store) Allocation(label string) (string, error) {
	var c string
	err := s.db.QueryRow(`SELECT commitment FROM private_allocations WHERE label = ?`, label).Scan(&c)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return c, err
}

// DeleteAllocation removes a private allocation.
func (s *Store) DeleteAllocation(label string) error {
	_, err := s.db.Exec(`DELETE FROM private_allocations WHERE label = ?`, label)
	return err
}

// Name returns who holds a public name.
func (s *Store) Name(name string) (string, error) {
	var aid string
	err := s.db.QueryRow(`SELECT aid FROM names WHERE name = ?`, name).Scan(&aid)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return aid, err
}

// ClaimName gives a name to aid, if nobody holds it, aid holds fewer than
// quota names, and it was not released by somebody else within holdBack.
// Claiming a name aid already holds succeeds and changes nothing.
func (s *Store) ClaimName(name, aid string, quota int, holdBack time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var holder string
	switch err := tx.QueryRow(`SELECT aid FROM names WHERE name = ?`, name).Scan(&holder); {
	case err == nil && holder == aid:
		return nil
	case err == nil:
		return ErrTaken
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	var released, releasedAt string
	switch err := tx.QueryRow(`SELECT aid, released_at FROM released_names WHERE name = ?`, name).Scan(&released, &releasedAt); {
	case err == nil && released != aid:
		at, _ := time.Parse(time.RFC3339, releasedAt)
		if s.now().Sub(at) < holdBack {
			return ErrTaken
		}
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM names WHERE aid = ?`, aid).Scan(&n); err != nil {
		return err
	}
	if n >= quota {
		return ErrQuota
	}
	if _, err := tx.Exec(`INSERT INTO names (name, aid, claimed_at) VALUES (?, ?, ?)`, name, aid, s.stamp()); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM released_names WHERE name = ?`, name); err != nil {
		return err
	}
	return tx.Commit()
}

// ErrQuota is returned when an identity already holds as many names or
// domains as the relay allows.
var ErrQuota = errors.New("this identity holds as many as this relay allows")

// ReleaseName gives up a name. Only its holder may.
func (s *Store) ReleaseName(name, aid string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var holder string
	switch err := tx.QueryRow(`SELECT aid FROM names WHERE name = ?`, name).Scan(&holder); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrNotFound
	case err != nil:
		return err
	case holder != aid:
		return ErrNotYours
	}
	if _, err := tx.Exec(`DELETE FROM names WHERE name = ?`, name); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO released_names (name, aid, released_at) VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET aid = excluded.aid, released_at = excluded.released_at`,
		name, aid, s.stamp()); err != nil {
		return err
	}
	return tx.Commit()
}

// Domain is a custom domain an identity has asked to be served at.
type Domain struct {
	Domain   string
	AID      string
	Verified bool
}

// Domain returns a custom domain's record.
func (s *Store) Domain(domain string) (Domain, error) {
	d := Domain{Domain: domain}
	var verified int
	err := s.db.QueryRow(`SELECT aid, verified FROM domains WHERE domain = ?`, domain).Scan(&d.AID, &verified)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	d.Verified = verified == 1
	return d, err
}

// RequestDomain records that aid wants to be served at domain, unverified.
// Asking again for a domain aid already asked for succeeds.
func (s *Store) RequestDomain(domain, aid string, quota int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var holder string
	switch err := tx.QueryRow(`SELECT aid FROM domains WHERE domain = ?`, domain).Scan(&holder); {
	case err == nil && holder == aid:
		return nil
	case err == nil:
		return ErrTaken
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM domains WHERE aid = ?`, aid).Scan(&n); err != nil {
		return err
	}
	if n >= quota {
		return ErrQuota
	}
	if _, err := tx.Exec(`INSERT INTO domains (domain, aid, verified, requested_at) VALUES (?, ?, 0, ?)`,
		domain, aid, s.stamp()); err != nil {
		return err
	}
	return tx.Commit()
}

// MarkDomainVerified records that the domain's DNS proved it is aid's.
func (s *Store) MarkDomainVerified(domain, aid string) error {
	res, err := s.db.Exec(`UPDATE domains SET verified = 1, verified_at = ? WHERE domain = ? AND aid = ?`,
		s.stamp(), domain, aid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ReleaseDomain stops serving a domain. Only its holder may.
func (s *Store) ReleaseDomain(domain, aid string) error {
	d, err := s.Domain(domain)
	if err != nil {
		return err
	}
	if d.AID != aid {
		return ErrNotYours
	}
	_, err = s.db.Exec(`DELETE FROM domains WHERE domain = ? AND aid = ?`, domain, aid)
	return err
}
