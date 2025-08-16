package sqlite

import (
	"cloud-storage/db_access"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/mattn/go-sqlite3"
)

type SqliteDb struct {
	*sql.DB
}

// TODO: maybe we should just use db.Exec() instead of this function
func (db *SqliteDb) Execute(query string, args ...any) (sql.Result, error) {
	const op = "db-access.sqlite.Exec"

	stmt, err := db.Prepare(query)
	if err != nil {
		return nil, fmt.Errorf("%s: db.Prepare: %w", op, err)
	}
	defer stmt.Close()

	res, err := stmt.Exec(args...)
	if err != nil {
		return nil, fmt.Errorf("%s: stmt.Exec: %w", op, err)
	}

	return res, nil
}

func New(path string) (db_access.DbAccess, error) {
	const op = "db-access.sqlite.New"

	sqlite, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("%s: sql.Open: %w", op, err)
	}

	db := &SqliteDb{sqlite}

	_, err = db.Execute(`
	CREATE TABLE IF NOT EXISTS files(
		id INTEGER PRIMARY KEY,
		generatedName TEXT NOT NULL UNIQUE,
		fileName TEXT NOT NULL
	);`)
	if err != nil {
		return nil, fmt.Errorf("%s: create files table: %w", op, err)
	}

	_, err = db.Execute(`
	CREATE TABLE IF NOT EXISTS decs(
		id INTEGER PRIMARY KEY,
		value TEXT NOT NULL,
		creationTime INTEGER NOT NULL
	);
	`)
	if err != nil {
		return nil, fmt.Errorf("%s: create decs table: %w", op, err)
	}

	_, err = db.Execute(`
	CREATE TABLE IF NOT EXISTS users(
		id INTEGER PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		passwordHash BLOB
	);
	`)
	if err != nil {
		return nil, fmt.Errorf("%s: create users table: %w", op, err)
	}

	_, err = db.Execute(`CREATE INDEX IF NOT EXISTS idx_genName ON files(generatedName);`)
	if err != nil {
		return nil, fmt.Errorf("%s: create index on files: %w", op, err)
	}

	return db, nil
}

func (db *SqliteDb) AddFile(generatedName string, filename string) error {
	const op = "db-access.sqlite.AddFile"

	_, err := db.Execute(
		`INSERT INTO files(generatedName, fileName) values(?,?)`,
		generatedName,
		filename,
	)
	if err != nil {
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
			// TODO: this is really dumb. Like wtf why are we getting table and column names from debug error string representation?
			errorMsg, _ := strings.CutPrefix(sqliteErr.Error(), "UNIQUE constraint failed: ")
			tableColumn := strings.Split(errorMsg, ".")
			return db_access.UniqueConstraintError{Table: tableColumn[0], Column: tableColumn[1]}
		}

		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (db *SqliteDb) RemoveFile(generatedName string) error {
	const op = "db-access.sqlite.RemoveFile"

	_, err := db.Execute(
		`DELETE FROM files WHERE generatedName = ?`,
		generatedName,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (db *SqliteDb) GetFile(generatedName string) (filename string, err error) {
	const op = "db-access.sqlite.GetFile"

	err = db.QueryRow(`SELECT fileName FROM files WHERE generatedName = ? LIMIT 1`, generatedName).Scan(&filename)
	if errors.Is(err, sql.ErrNoRows) {
		err = db_access.NoRowsError{}
	} else if err != nil {
		err = fmt.Errorf("%s: %w", op, err)
	}

	return
}

func (db *SqliteDb) GetDEC(id db_access.DecId) (db_access.DEC, error) {
	const op = "db-access.sqlite.GetDEC"

	stmt, err := db.Prepare(`
	SELECT * FROM decs WHERE id = ?
	`)
	if err != nil {
		return db_access.DEC{}, fmt.Errorf("%s: prepare statement: %w", op, err)
	}
	defer stmt.Close()

	var dec db_access.DEC
	err = stmt.QueryRow(id).Scan(&dec.Id, &dec.Value, &dec.CreationTime)
	if err != nil {
		return db_access.DEC{}, fmt.Errorf("%s: stmt.QueryRow: %w", op, err)
	}

	return dec, nil
}

func (db *SqliteDb) GetNewestDEC() (db_access.DEC, error) {
	const op = "db-access.sqlite.GetNewestDEC"

	// TODO: speed of this sql query
	stmt, err := db.Prepare(`SELECT * FROM decs ORDER BY creationTime DESC LIMIT 1`)
	if err != nil {
		return db_access.DEC{}, fmt.Errorf("%s: prepare statement: %w", op, err)
	}
	defer stmt.Close()

	var dec db_access.DEC
	err = stmt.QueryRow().Scan(&dec.Id, &dec.Value, &dec.CreationTime)
	if errors.Is(err, sql.ErrNoRows) {
		return db_access.DEC{}, db_access.NoRowsError{Table: "decs"}
	} else if err != nil {
		return db_access.DEC{}, fmt.Errorf("%s: stmt.QueryRow: %w", op, err)
	}

	return dec, nil
}

func (db *SqliteDb) AddDEC(dec *db_access.DEC) error {
	const op = "db-access.sqlite.AddDEC"

	res, err := db.Execute(
		`INSERT INTO decs(value, creationTime) values(?,?)`,
		dec.Value,
		dec.CreationTime,
	)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("%s: res.LastInsertId: %w", op, err)
	}

	dec.Id = db_access.DecId(id)

	return nil
}

func (db *SqliteDb) GetUser(user *db_access.User) (err error) {
	const op = "db-access.sqlite.GetUser"

	if user.Name == "" {
		err = db.QueryRow(`SELECT name, passwordHash FROM users WHERE id = ? LIMIT 1`, user.Id).Scan(&user.Name, &user.PasswordHash)
	} else {
		err = db.QueryRow(`SELECT id, passwordHash FROM users WHERE name = ? LIMIT 1`, user.Name).Scan(&user.Id, &user.PasswordHash)
	}

	if errors.Is(err, sql.ErrNoRows) {
		err = db_access.NoRowsError{Table: "users"}
	} else if err != nil {
		err = fmt.Errorf("%s: db.QueryRow: %w", op, err)
	}

	return
}

func (db *SqliteDb) AddUser(user *db_access.User) error {
	const op = "db-access.sqlite.AddUser"

	res, err := db.Exec(`INSERT INTO users(name, passwordHash) values(?, ?)`, user.Name, user.PasswordHash)
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) && sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique {
		return db_access.UniqueConstraintError{}
	} else if err != nil {
		return fmt.Errorf("%s: db.Exec: %w", op, err)
	}

	user.Id, err = res.LastInsertId()
	if err != nil {
		return fmt.Errorf("%s: res.LastInsertId: %w", op, err)
	}

	return nil
}
