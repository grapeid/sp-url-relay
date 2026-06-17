package store

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Enrollment struct {
	EnrollmentAID     string
	OOBIURL           string
	PublicKeyB64      string
	RootAIDEnrollment bool
	EnrolledAt        string
}

type Allocation struct {
	AllocationToken string
	RAID            string
	PublicHostname  string
	EnrollmentAID   string
	CreatedAt       string
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS enrollments (
			enrollment_aid TEXT PRIMARY KEY,
			oobi_url TEXT NOT NULL,
			public_key_b64 TEXT NOT NULL,
			root_aid_enrollment INTEGER DEFAULT 0,
			enrolled_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS allocations (
			allocation_token TEXT PRIMARY KEY,
			raid TEXT NOT NULL UNIQUE,
			public_hostname TEXT NOT NULL UNIQUE,
			enrollment_aid TEXT NOT NULL,
			created_at TEXT NOT NULL,
			FOREIGN KEY (enrollment_aid) REFERENCES enrollments(enrollment_aid)
		)`,
		`CREATE TABLE IF NOT EXISTS quarantine (
			public_hostname TEXT PRIMARY KEY,
			released_at TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_alloc_hostname ON allocations(public_hostname)`,
		`CREATE INDEX IF NOT EXISTS idx_alloc_enrollment ON allocations(enrollment_aid)`,
	}
	for _, q := range stmts {
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveEnrollment(e Enrollment) error {
	root := 0
	if e.RootAIDEnrollment {
		root = 1
	}
	_, err := s.db.Exec(`INSERT INTO enrollments (enrollment_aid, oobi_url, public_key_b64, root_aid_enrollment, enrolled_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(enrollment_aid) DO UPDATE SET
			oobi_url=excluded.oobi_url,
			public_key_b64=excluded.public_key_b64,
			root_aid_enrollment=excluded.root_aid_enrollment`,
		e.EnrollmentAID, e.OOBIURL, e.PublicKeyB64, root, e.EnrolledAt)
	return err
}

func (s *Store) GetEnrollment(aid string) (*Enrollment, error) {
	var e Enrollment
	var root int
	err := s.db.QueryRow(`SELECT enrollment_aid, oobi_url, public_key_b64, root_aid_enrollment, enrolled_at
		FROM enrollments WHERE enrollment_aid = ?`, aid).Scan(
		&e.EnrollmentAID, &e.OOBIURL, &e.PublicKeyB64, &root, &e.EnrolledAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	e.RootAIDEnrollment = root != 0
	return &e, nil
}

func (s *Store) HasEnrollment(aid string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM enrollments WHERE enrollment_aid = ?`, aid).Scan(&n)
	return n > 0, err
}

func (s *Store) SaveAllocation(a Allocation) error {
	_, err := s.db.Exec(`INSERT INTO allocations (allocation_token, raid, public_hostname, enrollment_aid, created_at)
		VALUES (?, ?, ?, ?, ?)`, a.AllocationToken, a.RAID, a.PublicHostname, a.EnrollmentAID, a.CreatedAt)
	return err
}

func (s *Store) GetAllocationByRAID(raid string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE raid = ?`, raid).Scan(&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *Store) GetAllocationByToken(token string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE allocation_token = ?`, token).Scan(&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *Store) GetAllocationByHostname(host string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE public_hostname = ?`, host).Scan(&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *Store) DeleteAllocation(token string) error {
	_, err := s.db.Exec(`DELETE FROM allocations WHERE allocation_token = ?`, token)
	return err
}

func (s *Store) QuarantineHostname(host string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO quarantine (public_hostname, released_at) VALUES (?, ?)`,
		host, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *Store) IsQuarantined(host string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM quarantine WHERE public_hostname = ?`, host).Scan(&n)
	return n > 0, err
}

func (s *Store) MintAllocationToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("alloc_%x", b), nil
}