package config

// SystemLogFile is the log file used when logging.file is empty.
const SystemLogFile = "/var/log/pam-ciba/pam-ciba.log"

// LogFilePath answers logging.file, or SystemLogFile when it is empty.
func (c *Config) LogFilePath() (string, error) {
	if c.Logging.File != "" {
		return c.Logging.File, nil
	}
	return SystemLogFile, nil
}
