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
	// secure_delete overwrites what is deleted, so a removed row is not left
	// readable in free pages of the file.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=secure_delete(ON)")
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
		`CREATE TABLE IF NOT EXISTS nonces (
			digest TEXT PRIMARY KEY,
			expires_at INTEGER NOT NULL
		)`,
		fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion),
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	// The earlier schema linked allocations to the identities that made them.
	// Dropping its tables leaves their bytes in the file's free pages and in
	// the write-ahead log; rewrite both so nothing of it survives.
	if _, err := s.db.Exec(`VACUUM`); err != nil {
		return fmt.Errorf("migrate: vacuum: %w", err)
	}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("migrate: checkpoint: %w", err)
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
	// Only the month: an exact time could be matched against when an identity
	// was connected, which would rebuild the link this table does not keep.
	_, err := s.db.Exec(`INSERT INTO private_allocations (label, commitment, created_at) VALUES (?, ?, ?)`,
		label, commitment, s.now().UTC().Format("2006-01"))
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
	// A name released within the hold-back still counts against its
	// releaser's quota, so claiming and releasing cannot lock up more names
	// than the quota allows.
	var n int
	cutoff := s.now().Add(-holdBack).UTC().Format(time.RFC3339)
	if err := tx.QueryRow(`SELECT
		(SELECT COUNT(*) FROM names WHERE aid = ?) +
		(SELECT COUNT(*) FROM released_names WHERE aid = ? AND released_at > ? AND name != ?)`,
		aid, aid, cutoff, name).Scan(&n); err != nil {
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
// Asking again for a domain aid already asked for succeeds. A request that
// another identity made and never proved within pendingFor lapses, so nobody
// can hold a domain they cannot prove. A domain held but unproved by another
// identity is still ErrTaken here; its real owner proves it with
// VerifyDomainFor, which takes it over.
func (s *Store) RequestDomain(domain, aid string, quota int, pendingFor time.Duration) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := expirePending(tx, s.now().Add(-pendingFor)); err != nil {
		return err
	}
	var holder string
	switch err := tx.QueryRow(`SELECT aid FROM domains WHERE domain = ?`, domain).Scan(&holder); {
	case err == nil && holder == aid:
		return nil
	case err == nil:
		return ErrTaken
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	if err := underQuota(tx, aid, quota); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO domains (domain, aid, verified, requested_at) VALUES (?, ?, 0, ?)`,
		domain, aid, s.stamp()); err != nil {
		return err
	}
	return tx.Commit()
}

func expirePending(tx *sql.Tx, before time.Time) error {
	_, err := tx.Exec(`DELETE FROM domains WHERE verified = 0 AND requested_at < ?`, before.UTC().Format(time.RFC3339))
	return err
}

func underQuota(tx *sql.Tx, aid string, quota int) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM domains WHERE aid = ?`, aid).Scan(&n); err != nil {
		return err
	}
	if n >= quota {
		return ErrQuota
	}
	return nil
}

// VerifyDomainFor records that the domain's DNS has just proved it is aid's.
// The proof decides, not who asked first: an unproved request by another
// identity is replaced. A domain another identity has proved is ErrTaken; the
// caller re-checks that identity's proof first and calls UnverifyDomain if it
// no longer holds.
func (s *Store) VerifyDomainFor(domain, aid string, quota int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var holder string
	var verified int
	switch err := tx.QueryRow(`SELECT aid, verified FROM domains WHERE domain = ?`, domain).Scan(&holder, &verified); {
	case err == nil && holder == aid:
	case err == nil && verified == 1:
		return ErrTaken
	case err == nil:
		if _, err := tx.Exec(`DELETE FROM domains WHERE domain = ?`, domain); err != nil {
			return err
		}
		fallthrough
	case errors.Is(err, sql.ErrNoRows):
		if err := underQuota(tx, aid, quota); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO domains (domain, aid, verified, requested_at) VALUES (?, ?, 0, ?)`,
			domain, aid, s.stamp()); err != nil {
			return err
		}
	default:
		return err
	}
	if _, err := tx.Exec(`UPDATE domains SET verified = 1, verified_at = ? WHERE domain = ? AND aid = ?`,
		s.stamp(), domain, aid); err != nil {
		return err
	}
	return tx.Commit()
}

// UnverifyDomain stops serving a domain whose proof no longer holds. It stays
// requested by the same identity, which may prove it again.
func (s *Store) UnverifyDomain(domain string) error {
	_, err := s.db.Exec(`UPDATE domains SET verified = 0, verified_at = NULL, requested_at = ? WHERE domain = ?`,
		s.stamp(), domain)
	return err
}

// VerifiedDomains lists every proved domain.
func (s *Store) VerifiedDomains() ([]Domain, error) {
	rows, err := s.db.Query(`SELECT domain, aid FROM domains WHERE verified = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d := Domain{Verified: true}
		if err := rows.Scan(&d.Domain, &d.AID); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UseNonce records a control request's nonce digest until expires. It
// reports false if the digest is already recorded and unexpired: a replay.
// Kept on disk so a restart does not make a request seconds old usable again.
func (s *Store) UseNonce(digest string, expires time.Time) (bool, error) {
	now := s.now().Unix()
	if _, err := s.db.Exec(`DELETE FROM nonces WHERE expires_at < ?`, now); err != nil {
		return false, err
	}
	res, err := s.db.Exec(`INSERT OR IGNORE INTO nonces (digest, expires_at) VALUES (?, ?)`, digest, expires.Unix())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
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
