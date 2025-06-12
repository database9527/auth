package main

import (
	"os"
	"testing"
)

func TestLoadConfig_Success(t *testing.T) {
	// Create a temporary valid config file
	content := []byte(`{
		"monitor_config": {
			"group_1": [{"node_id": "local1", "type": "local"}],
			"group_2": [{"node_id": "remote1", "type": "remote", "api": "http://remote.api"}]
		}
	}`)
	tmpfile, err := os.CreateTemp("", "test_config_*.json")
	if err != nil {
		t.Fatalf("Failed to create temp config file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // Clean up

	if _, err := tmpfile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp config file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp config file: %v", err)
	}

	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Errorf("LoadConfig() error = %v, wantErr %v", err, false)
	}
	if config == nil {
		t.Errorf("LoadConfig() config = nil, want non-nil")
		return
	}
	if len(config.Monitor.Group1) != 1 || config.Monitor.Group1[0].NodeID != "local1" {
		t.Errorf("Config not loaded correctly for Group1")
	}
	if len(config.Monitor.Group2) != 1 || config.Monitor.Group2[0].Api != "http://remote.api" {
		t.Errorf("Config not loaded correctly for Group2")
	}
}

func TestLoadConfig_FileNotExists(t *testing.T) {
	_, err := LoadConfig("non_existent_config.json")
	if err == nil {
		t.Errorf("LoadConfig() with non-existent file, error = nil, wantErr %v", true)
	}
}
