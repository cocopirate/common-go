// Package dbx provides shared database helpers:
//   - NewPostgres: open and configure a GORM PostgreSQL connection
//   - NewMySQL: open and configure a GORM MySQL connection
//   - RunMigrations: run golang-migrate from an embed.FS
//
// These helpers eliminate the identical newDB/runMigrations boilerplate
// duplicated across every service cmd/main.go.
package dbx

import (
	"embed"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"go.uber.org/zap"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Options controls connection pool settings and debug logging.
type Options struct {
	MaxOpenConns int
	MaxIdleConns int
	// Debug enables GORM SQL logging at Info level.
	Debug bool
}

// DefaultOptions returns sensible defaults used across services.
func DefaultOptions(debug bool) Options {
	return Options{
		MaxOpenConns: 30,
		MaxIdleConns: 10,
		Debug:        debug,
	}
}

// NewPostgres opens a GORM PostgreSQL connection with the given DSN and options.
// The DSN should be a full postgres:// URL (sslmode should be set by the caller).
func NewPostgres(dsn string, opts Options) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), gormConfig(opts.Debug))
	if err != nil {
		return nil, fmt.Errorf("dbx: open postgres: %w", err)
	}
	return configurePool(db, opts)
}

// NewMySQL opens a GORM MySQL connection with the given DSN.
// Returns (nil, nil) when dsn is empty, so callers can treat an absent DSN as
// "feature disabled" without special-casing.
func NewMySQL(dsn string, opts Options) (*gorm.DB, error) {
	if dsn == "" {
		return nil, nil
	}
	db, err := gorm.Open(mysql.Open(dsn), gormConfig(opts.Debug))
	if err != nil {
		return nil, fmt.Errorf("dbx: open mysql: %w", err)
	}
	return configurePool(db, opts)
}

// RunMigrations runs all pending migrations from the given embed.FS.
// The FS should contain *.up.sql / *.down.sql files at its root.
// If no migrations are pending (migrate.ErrNoChange) the function returns nil.
func RunMigrations(databaseURL string, fs embed.FS, log *zap.Logger) error {
	src, err := iofs.New(fs, ".")
	if err != nil {
		return fmt.Errorf("dbx: migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, databaseURL)
	if err != nil {
		return fmt.Errorf("dbx: migration init: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("dbx: migration up: %w", err)
	}
	log.Info("database migrations applied")
	return nil
}

// ─── private helpers ─────────────────────────────────────────────────────────

func gormConfig(debug bool) *gorm.Config {
	level := gormlogger.Silent
	if debug {
		level = gormlogger.Info
	}
	return &gorm.Config{
		Logger: gormlogger.Default.LogMode(level),
	}
}

func configurePool(db *gorm.DB, opts Options) (*gorm.DB, error) {
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("dbx: get sql.DB: %w", err)
	}
	if opts.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(opts.MaxOpenConns)
	}
	if opts.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(opts.MaxIdleConns)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db, nil
}
