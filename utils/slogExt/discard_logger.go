package slogext

import (
	"context"
	"log/slog"
)

func NewDiscardLogger() *slog.Logger {
	return slog.New(discardHandler{})
}

type discardHandler struct {}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return false
}

func (discardHandler) Handle(context.Context, slog.Record) error {
	return nil
}

func (h discardHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h discardHandler) WithGroup(name string) slog.Handler {
	return h
}
