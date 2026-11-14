package config

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
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
	Auth     AuthConfig
	Cookie   CookieConfig
}

type AppConfig struct{ Env string }

func (a AppConfig) IsProd() bool { return a.Env == "prod" }

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

type AuthConfig struct {
	JWTSecret           []byte
	JWTIssuer           string
	AccessTokenTTL      time.Duration
	RefreshTokenTTL     time.Duration
	MaxConcurrentHashes int
}

type CookieConfig struct {
	Domain   string
	Secure   bool
	SameSite http.SameSite
	Path     string
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
	default:
		return nil, fmt.Errorf("config: LOG_FORMAT must be text|json, got %q", logFormat)
	}

	rawSecret, err := mustEnv("JWT_SECRET")
	if err != nil {
		return nil, err
	}
	secret, err := parseJWTSecret(rawSecret)
	if err != nil {
		return nil, err
	}
	jwtIssuer, err := mustEnv("JWT_ISSUER")
	if err != nil {
		return nil, err
	}
	accessTTL, err := mustDuration("ACCESS_TOKEN_TTL")
	if err != nil {
		return nil, err
	}
	refreshTTL, err := mustDuration("REFRESH_TOKEN_TTL")
	if err != nil {
		return nil, err
	}
	maxHashes, err := optInt32("AUTH_MAX_CONCURRENT_HASHES", 0)
	if err != nil {
		return nil, err
	}

	cookieSecure, err := optBool("COOKIE_SECURE", false)
	if err != nil {
		return nil, err
	}
	if env == "prod" && !cookieSecure {
		return nil, fmt.Errorf("config: COOKIE_SECURE must be true when APP_ENV=prod")
	}
	cookieDomain := os.Getenv("COOKIE_DOMAIN")

	if cookieDomain != "" && !isValidHostname(cookieDomain) {
		return nil, fmt.Errorf(
			"config: COOKIE_DOMAIN=%q is not a valid hostname "+
				"(this may indicate a corrupted .env — check for missing newlines)",
			cookieDomain)
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
		Auth: AuthConfig{
			JWTSecret:           secret,
			JWTIssuer:           jwtIssuer,
			AccessTokenTTL:      accessTTL,
			RefreshTokenTTL:     refreshTTL,
			MaxConcurrentHashes: int(maxHashes),
		},
		Cookie: CookieConfig{
			Domain:   cookieDomain,
			Secure:   cookieSecure,
			SameSite: http.SameSiteStrictMode,
			Path:     "/api/v1/auth",
		},
	}, nil
}

// parseJWTSecret accepts base64 (standard or url), hex, or a raw ≥32-byte
// string. The first encoding that yields ≥32 bytes wins.
func parseJWTSecret(raw string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) >= 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(b) >= 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) >= 32 {
		return b, nil
	}
	if len(raw) >= 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("config: JWT_SECRET must decode to at least 32 bytes")
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

func optBool(key string, def bool) (bool, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("config: %s must be true/false: %w", key, err)
	}
	return b, nil
}

// isValidHostname accepts an empty string (host-only cookie) or a
// hostname that passes basic sanity checks: no equals, no spaces, no
// slashes, no colons (port is not allowed in Cookie.Domain).
func isValidHostname(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '.', r == '-':
			// ok
		default:
			return false
		}
	}
	return len(s) < 254 && !strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".")
}
