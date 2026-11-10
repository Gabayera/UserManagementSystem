package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	App      AppConfig
	Server   ServerConfig
	Database DatabaseConfig
	Log      LogConfig
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

type LogConfig struct {
	Level  string
	Format string
}

func Load() (*Config, error) {
	env, err := mustEnv("APP_ENV")
	if err != nil {
		return nil, err
	}

	if env != "dev" && env != "prod" {
		return nil, fmt.Errorf("config: APP_ENV must be dev or prod, got %q", env)
	}

	addr, err := mustEnv("SERVER_ADDR")
	if err != nil {
		return nil, err
	}

	readTimeout, err := mustDuration("SERVER_READ_TIMEOUT")
	if err != nil {
		return nil, err
	}

	writeTimeout, err := mustDuration("SERVER_WRITE_TIMEOUT")
	if err != nil {
		return nil, err
	}

	shutdownTimeout, err := mustDuration("SERVER_SHUTDOWN_TIMEOUT")
	if err != nil {
		return nil, err
	}

	dbURL, err := mustEnv("DATABASE_URL")
	if err != nil {
		return nil, err
	}

	maxConns, err := optInt32("DB_MAX_CONNS", 10)
	if err != nil {
		return nil, err
	}
	minConns, err := optInt32("DB_MIN_CONNS", 1)
	if err != nil {
		return nil, err
	}
	maxLifetime, err := optDuration("DB_MAX_CONN_LIFETIME", time.Hour)
	if err != nil {
		return nil, err
	}

	maxIdle, err := optDuration("DB_MAX_CONN_IDLE_TIME", 30*time.Minute)
	if err != nil {
		return nil, err
	}
	healthPeriod, err := optDuration("DB_HEALTH_CHECK_PERIOD", time.Minute)
	if err != nil {
		return nil, err
	}

	logLevel, err := mustEnv("LOG_LEVEL")
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(logLevel) {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("config: LOG_LEVEL must be debug|info|warn|error, got %q", logLevel)
	}

	logFormat, err := mustEnv("LOG_FORMAT")
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(logFormat) {
	case "text", "json":
		// valid — fall through to end of switch
	default:
		return nil, fmt.Errorf("config: LOG_FORMAT must be text|json, got %q", logFormat)
	}

	return &Config{
		App: AppConfig{Env: env},
		Server: ServerConfig{
			Addr:            addr,
			ReadTimeout:     readTimeout,
			WriteTimeout:    writeTimeout,
			ShutdownTimeout: shutdownTimeout,
		},
		Database: DatabaseConfig{
			URL:               dbURL,
			MaxConns:          maxConns,
			MinConns:          minConns,
			MaxConnLifetime:   maxLifetime,
			MaxConnIdleTime:   maxIdle,
			HealthCheckPeriod: healthPeriod,
		},
		Log: LogConfig{Level: logLevel, Format: logFormat},
	}, nil
}

func mustEnv(key string) (string, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return "", fmt.Errorf("config: required env %s not set", key)
	}
	return v, nil
}

func mustDuration(key string) (time.Duration, error) {
	v, err := mustEnv(key)
	if err != nil {
		return 0, err
	}

	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a duration: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive, got %s", key, d)
	}
	return d, nil
}

func optDuration(key string, def time.Duration) (time.Duration, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be a duration: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s must be positive, got %s", key, d)
	}
	return d, nil
}

func optInt32(key string, def int32) (int32, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s must be an integer: %w", key, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("config: %s must be >= 0, got %d", key, n)
	}
	return int32(n), nil
}
