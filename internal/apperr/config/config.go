package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	App      AppConfig
	Server   ServerConfig
	Database DatabaseConfig
	Log      LogConfing
}

type AppConfig struct {
	Env string
}

func (a AppConfig) IsProd() bool {
	return a.Env == "prod"
}

type ServerConfig struct {
	Addr            string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type DatabaseConfig struct {
	URL               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
}

type LogConfing struct {
	Level  string // "debug" | "info" | "warn" | "error"
	Format string // "text" | "json"
}

// func Load() (*Config, error) {

// }

func mustEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("required env %s not set", key)
	}
	return v, nil
}

func parseDuration(key, raw string) (time.Duration, error) {
	t, err := time.ParseDuration(key)
	if err != nil || t < 0 {
		return 0, err
	}
	return t, nil
}

// func parseInt32(key, raw string) (int32, error) {
// 	number, err := strconv.ParseInt(key)
// }
