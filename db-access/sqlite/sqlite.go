package sqlite

import (
	dbaccess "cloud-storage/db-access"
	"database/sql"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"
)

type SqliteDb struct {
	*sql.DB
}

func New(path string) (*SqliteDb, error) {
	const op = "db-access.sqlite.New"

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	stmt, err := db.Prepare(`
	CREATE TABLE IF NOT EXISTS files(
		id INTEGER PRIMARY KEY,
		generatedName TEXT NOT NULL UNIQUE,
		fileName TEXT NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_genName ON files(generatedName);
	`)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &SqliteDb{db}, nil
}

func (db *SqliteDb) AddFile(generatedName string, filename string) error {
	const op = "db-access.sqlite.AddFile"

	stmt, err := db.Prepare(`
	INSERT INTO files(generatedName, fileName) values(?,?)
	`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(generatedName, filename)
	if err != nil {
		if sqliteErr, ok := err.(sqlite3.Error); ok && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			errorMsg, _ := strings.CutPrefix(sqliteErr.Error(), "UNIQUE constraint failed: ")
			tableColumn := strings.Split(errorMsg, ".")
			return dbaccess.UniqueConstraintError{Table: tableColumn[0], Column: tableColumn[1]}
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (db *SqliteDb) RemoveFile(generatedName string) error {
	const op = "db-access.sqlite.RemoveFile"
	
	stmt, err := db.Prepare(`
	DELETE FROM files WHERE generatedName = ?
	`)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer stmt.Close()
	
	_, err = stmt.Exec(generatedName)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	
	return nil
}
