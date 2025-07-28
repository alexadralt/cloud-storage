package config

import (
	"log"
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

const (
	EnvProd  string = "prod"
	EnvLocal string = "local"
	EnvDev   string = "dev"
)

type AppConfig struct {
	Environment     string `json:"environment" env-default:"prod"`
	DbPath          string `json:"db-path" env-required:"true"`
	MaxUploadSize   int64  `json:"max-upload-size" env-default:"1024"`
	FileStoragePath string `json:"file-storage-path" env-required:"true"`
	HTTPConfig
}

type HTTPConfig struct {
	Address      string        `json:"address" env-default:"0.0.0.0:8080"`
	WriteTimeout time.Duration `json:"write-timeout" env-default:"0s"`
	IdleTimeout  time.Duration `json:"idle-timeout" env-default:"30s"`
	ReadTimout   time.Duration `json:"read-timeout" env-default:"0s"`
}

const configPathEnvVarName = "CONFIG_PATH"

func MustLoad() *AppConfig {
	configPath := os.Getenv(configPathEnvVarName)
	if configPath == "" {
		log.Fatalf("%s environment variable is not set", configPathEnvVarName)
	}

	if _, err := os.Stat(configPath); err != nil {
		log.Fatalf("Could not read config file: %s", err)
	}

	var appConfig AppConfig

	if err := cleanenv.ReadConfig(configPath, &appConfig); err != nil {
		log.Fatalf("Could not read config file: %s", err)
	}

	return &appConfig
}
