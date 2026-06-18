package store

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
)

type postgresStore struct {
	db *sql.DB
}

func (s *postgresStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS enrollments (
			enrollment_aid TEXT PRIMARY KEY,
			oobi_url TEXT NOT NULL,
			public_key_b64 TEXT NOT NULL,
			root_aid_enrollment INT DEFAULT 0,
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

func (s *postgresStore) Close() error { return s.db.Close() }

func (s *postgresStore) SaveEnrollment(e Enrollment) error {
	root := 0
	if e.RootAIDEnrollment {
		root = 1
	}
	_, err := s.db.Exec(`INSERT INTO enrollments (enrollment_aid, oobi_url, public_key_b64, root_aid_enrollment, enrolled_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT(enrollment_aid) DO UPDATE SET
			oobi_url=EXCLUDED.oobi_url,
			public_key_b64=EXCLUDED.public_key_b64,
			root_aid_enrollment=EXCLUDED.root_aid_enrollment`,
		e.EnrollmentAID, e.OOBIURL, e.PublicKeyB64, root, e.EnrolledAt)
	return err
}

func (s *postgresStore) GetEnrollment(aid string) (*Enrollment, error) {
	var e Enrollment
	var root int
	err := s.db.QueryRow(`SELECT enrollment_aid, oobi_url, public_key_b64, root_aid_enrollment, enrolled_at
		FROM enrollments WHERE enrollment_aid = $1`, aid).Scan(
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

func (s *postgresStore) HasEnrollment(aid string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM enrollments WHERE enrollment_aid = $1`, aid).Scan(&n)
	return n > 0, err
}

func (s *postgresStore) SaveAllocation(a Allocation) error {
	_, err := s.db.Exec(`INSERT INTO allocations (allocation_token, raid, public_hostname, enrollment_aid, created_at)
		VALUES ($1, $2, $3, $4, $5)`,
		a.AllocationToken, a.RAID, a.PublicHostname, a.EnrollmentAID, a.CreatedAt)
	return err
}

func (s *postgresStore) GetAllocationByRAID(raid string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE raid = $1`, raid).Scan(
		&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *postgresStore) GetAllocationByToken(token string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE allocation_token = $1`, token).Scan(
		&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *postgresStore) GetAllocationByHostname(host string) (*Allocation, error) {
	var a Allocation
	err := s.db.QueryRow(`SELECT allocation_token, raid, public_hostname, enrollment_aid, created_at
		FROM allocations WHERE public_hostname = $1`, host).Scan(
		&a.AllocationToken, &a.RAID, &a.PublicHostname, &a.EnrollmentAID, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &a, err
}

func (s *postgresStore) DeleteAllocation(token string) error {
	_, err := s.db.Exec(`DELETE FROM allocations WHERE allocation_token = $1`, token)
	return err
}

func (s *postgresStore) QuarantineHostname(host string) error {
	_, err := s.db.Exec(`INSERT INTO quarantine (public_hostname, released_at) VALUES ($1, $2)
		ON CONFLICT DO NOTHING`,
		host, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (s *postgresStore) IsQuarantined(host string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM quarantine WHERE public_hostname = $1`, host).Scan(&n)
	return n > 0, err
}

func (s *postgresStore) MintAllocationToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("alloc_%x", b), nil
}
