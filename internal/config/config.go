// Package config loads and provides the YAML configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/STARTcloud/pam-ciba/internal/configengine"
	"github.com/STARTcloud/pam-ciba/internal/safepath"
)

// SystemDir is the configuration directory used when neither --config nor CONFIG_DIR names one.
const SystemDir = "/etc/pam-ciba"

// Config is the typed view over the configuration file.
type Config struct {
	Provider ProviderConfig    `yaml:"provider" json:"provider"`
	Approval ApprovalConfig    `yaml:"approval" json:"approval"`
	Users    map[string]string `yaml:"users"    json:"users"`
	Logging  LoggingConfig     `yaml:"logging"  json:"logging"`

	dir    string
	engine *configengine.Engine
}

// DefaultDir answers CONFIG_DIR when set, else SystemDir.
func DefaultDir() (string, error) {
	if dir := os.Getenv("CONFIG_DIR"); dir != "" {
		return safepath.CleanAbs(dir)
	}
	return SystemDir, nil
}

// Options shape one load.
type Options struct {
	Dir  string
	Seed bool
}

// Load builds the engine over the configuration directory, loads the file and fills the typed view.
func Load(options Options) (*Config, error) {
	dir := options.Dir
	if dir == "" {
		defaultDir, err := DefaultDir()
		if err != nil {
			return nil, err
		}
		dir = defaultDir
	}
	dir, err := safepath.CleanAbs(dir)
	if err != nil {
		return nil, err
	}
	if options.Seed {
		if serr := ensureSeeds(dir); serr != nil {
			return nil, serr
		}
	}
	cfg := &Config{dir: dir}
	cfg.engine = configengine.New(dir, Names, SchemaFS(), configengine.Hooks{
		Writable: cfg.codeRules,
	})
	if lerr := cfg.engine.Load(); lerr != nil {
		return nil, lerr
	}
	if ferr := cfg.fill(); ferr != nil {
		return nil, ferr
	}
	return cfg, nil
}

func (c *Config) fill() error {
	merged := map[string]any{}
	for _, name := range Names {
		for key, value := range c.engine.Get(name) {
			if key == "schemaVersion" {
				continue
			}
			merged[key] = value
		}
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return err
	}
	fresh := Config{dir: c.dir, engine: c.engine}
	if uerr := json.Unmarshal(raw, &fresh); uerr != nil {
		return fmt.Errorf("fill configuration: %w", uerr)
	}
	*c = fresh
	return nil
}

// Engine answers the configuration engine.
func (c *Config) Engine() *configengine.Engine {
	return c.engine
}

// Dir answers the configuration directory.
func (c *Config) Dir() string {
	return c.dir
}

// LoginHint answers the provider account a local account signs in as, and whether one is mapped.
func (c *Config) LoginHint(localUser string) (string, bool) {
	hint, ok := c.Users[localUser]
	return hint, ok && hint != ""
}
