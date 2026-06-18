package store

import (
	"database/sql"
	"fmt"
	"os"
)

// UsePostgres switches the backend.
//
//	false → SQLite  (development / standalone Linux)
//	true  → PostgreSQL via DATABASE_URL (Replit production)
const UsePostgres = false

// Store is the persistence interface implemented by both backends.
type Store interface {
	Close() error
	SaveEnrollment(Enrollment) error
	GetEnrollment(aid string) (*Enrollment, error)
	HasEnrollment(aid string) (bool, error)
	SaveAllocation(Allocation) error
	GetAllocationByRAID(raid string) (*Allocation, error)
	GetAllocationByToken(token string) (*Allocation, error)
	GetAllocationByHostname(host string) (*Allocation, error)
	DeleteAllocation(token string) error
	QuarantineHostname(host string) error
	IsQuarantined(host string) (bool, error)
	MintAllocationToken() (string, error)
}

// Open returns the correct backend based on the UsePostgres constant.
func Open(sqlitePath string) (Store, error) {
	if UsePostgres {
		dsn := os.Getenv("DATABASE_URL")
		if dsn == "" {
			return nil, fmt.Errorf("DATABASE_URL is not set")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, err
		}
		s := &postgresStore{db: db}
		if err := s.migrate(); err != nil {
			db.Close()
			return nil, err
		}
		return s, nil
	}
	return openSQLite(sqlitePath)
}
