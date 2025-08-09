package db_access

import (
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

type UniqueConstraintError struct {
	Column string
	Table  string
}

func (err UniqueConstraintError) Error() string {
	return strings.Join([]string{"unique constraint violation: ", err.Table, ".", err.Column}, "")
}

type NoRowsError struct {
	Table string
}

func (err NoRowsError) Error() string {
	return fmt.Sprintf("no rows were found in table %s", err.Table)
}

type Time time.Time

func (t Time) Value() (driver.Value, error) {
	return time.Time(t).Unix(), nil
}

func (t *Time) Scan(src any) error {
	const op = "dbaccess.Time.Scan"

	if src == nil {
		*t = Time{}
		return nil
	}

	if unixTime, ok := src.(int64); ok {
		*t = Time(time.Unix(unixTime, 0))
		return nil
	}

	return fmt.Errorf("%s: src is not an int64, but a %T", op, src)
}

type DecId int64

type DEC struct {
	Id           DecId
	Value        string
	CreationTime Time
}

type DbAccess interface {
	AddFile(generatedName string, filename string) error
	RemoveFile(generatedName string) error
	GetDEC(id DecId) (DEC, error)
	GetNewestDEC() (DEC, error)
	AddDEC(dec *DEC) error
}
