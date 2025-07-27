package main

import (
	"cloud-storage/api"
	"cloud-storage/config"
	"cloud-storage/db-access/sqlite"
	slogext "cloud-storage/utils/slogExt"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func main() {
	appConfig := config.MustLoad()
	log := setupLogger(appConfig.Environment).With(
		slog.String("env", appConfig.Environment),
	)

	log.Debug("Debug messages are enabled")

	db, err := sqlite.New(appConfig.DbPath)
	if err != nil {
		log.Error("Could not load a db", slogext.Error(err))
		os.Exit(1)
	}

	err = func() error {
		if info, err := os.Stat(appConfig.FileStoragePath); err != nil && errors.Is(err, os.ErrNotExist) {
			fullPath, err := filepath.Abs(appConfig.FileStoragePath)
			if err != nil {
				return err
			}

			log.Info("Storage dir does not exists; creating", slog.String("path", fullPath))
			err = os.Mkdir(fullPath, os.ModeDir)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if !info.IsDir() {
			return errors.New("file already exists with such name")
		}
		
		return nil
	}()
	
	if err != nil {
		log.Error("Could not create storage dir", slogext.Error(err))
		os.Exit(1)
	}
	

	r := chi.NewRouter()

	r.Route("/api", func(r chi.Router) {
		r.Use(middleware.RequestID)
		r.Use(slogext.Logger(log))
		r.Use(middleware.Recoverer)

		r.Post("/upload", api.FileUpload(db, appConfig.MaxUploadSize, appConfig.FileStoragePath))
	})

	log.Info(
		"Starting server",
		slog.String("address", appConfig.Address),
		slog.Int64("max-upload-size", appConfig.MaxUploadSize),
	)

	// TODO: understand timeouts
	server := &http.Server{
		Addr:         appConfig.Address,
		IdleTimeout:  appConfig.IdleTimeout,
		WriteTimeout: appConfig.Timeout,
		Handler:      r,
	}

	log.Error("Server terminated", slog.String("server-crash", server.ListenAndServe().Error()))
}

func setupLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case config.EnvLocal:
		log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case config.EnvDev:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	case config.EnvProd:
		log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	return log
}
