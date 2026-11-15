package config

import (
	"path/filepath"
)

// LogFilePath returns the configured log file, defaulting to
// <config dir>/logs/pam-ciba.log.
func (c *Config) LogFilePath() (string, error) {
	if c.Logging.File != "" {
		return c.Logging.File, nil
	}
	return filepath.Join(c.dir, "logs", "pam-ciba.log"), nil
}
