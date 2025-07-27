package slogext

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func Error(err error) slog.Attr {
	return slog.Attr{
		Key: "error",
		Value: slog.StringValue(err.Error()),
	}
}

type LoggerKey string

const Log LoggerKey = "log"

func LogWithOp(op string, ctx context.Context) *slog.Logger {
	log, ok := ctx.Value(Log).(*slog.Logger)
	if !ok {
		return nil
	}
	
	return log.With(slog.String("op", op))
}

func Logger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		log = log.With(
            slog.String("component", "middleware/logger"),
        )

        log.Debug("Logger middleware is enabled")
		
		fn := func(w http.ResponseWriter, r *http.Request) {
			logWithId := log.With(
				slog.String("request-id", middleware.GetReqID(r.Context())),
			)
			
            log := logWithId.With(
                slog.String("method", r.Method),
                slog.String("url", r.URL.Path),
                slog.String("remote-addr", r.RemoteAddr),
                slog.String("user-agent", r.UserAgent()),
            )
            
            ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

            t1 := time.Now()
			
			log.Info("Accepted new request", slog.String("request-time", t1.String()))
            
            defer func() {
                log.Info("Completed request",
                    slog.Int("status", ww.Status()),
                    slog.Int("bytes-written", ww.BytesWritten()),
                    slog.String("duration", time.Since(t1).String()),
                )
            }()
			
			rr := r.WithContext(context.WithValue(r.Context(), Log, logWithId))

            next.ServeHTTP(ww, rr)
		}
		
		return http.HandlerFunc(fn)
	}
}
