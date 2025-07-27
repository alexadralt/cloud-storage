package dbaccess

import "strings"

type UniqueConstraintError struct {
	Column string
	Table  string
}

func (err UniqueConstraintError) Error() string {
	return strings.Join([]string{ "unique constraint violation: ", err.Table, ".", err.Column }, "")
}

type DbAccess interface {
	AddFile(generatedName string, filename string) error
}
