package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

// NodeConfig defines the structure for a monitoring node
type NodeConfig struct {
	NodeID string `json:"node_id"`
	Type   string `json:"type"` // "local" or "remote"
	Api    string `json:"api,omitempty"` // API URL for remote nodes
}

// MonitorConfig holds the group configurations
type MonitorConfig struct {
	Group1 []NodeConfig `json:"group_1"`
	Group2 []NodeConfig `json:"group_2"`
}

// AppConfig is the top-level configuration structure
type AppConfig struct {
	Monitor MonitorConfig `json:"monitor_config"`
}

// Global config variable
var globalAppConfig *AppConfig

// LoadConfig reads the configuration file and unmarshals it
func LoadConfig(filepath string) (*AppConfig, error) {
	configFile, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer configFile.Close()

	bytes, err := ioutil.ReadAll(configFile)
	if err != nil {
		return nil, err
	}

	var config AppConfig
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}
	globalAppConfig = &config // Store loaded config globally
	return &config, nil
}
