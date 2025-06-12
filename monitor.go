package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Target represents a monitoring target, similar to PHP structure
type Target struct {
	NodeGroup string `json:"node_group"` // 1 for group_1, 2 for group_2
	Type      string `json:"type"`       // http, ping, tcp
	Target    string `json:"target"`     // IP address or hostname
	Port      int    `json:"port"`
	Path      string `json:"path"`       // For http
	Host      string `json:"host"`       // For http Host header
	Timeout   int    `json:"timeout"`    // In seconds
}

// MonitorResult represents the result of a single check
type MonitorResult struct {
	NodeID  string `json:"node_id"`
	Success int    `json:"success"` // 1 for true, 0 for false
	Target  string `json:"target"`
}

// checkHttp performs an HTTP check
func checkHttp(target Target) bool {
	if target.Timeout <= 0 || target.Timeout > 3 {
		target.Timeout = 3 // Default/max timeout
	}
	if target.Port == 0 {
		target.Port = 80
	}
	if target.Path == "" {
		target.Path = "/"
	}

	url := fmt.Sprintf("http://%s:%d%s", target.Target, target.Port, target.Path)
	if target.Port == 80 {
		url = fmt.Sprintf("http://%s%s", target.Target, target.Path)
	}
    if target.Port == 443 { // Basic https support
        url = fmt.Sprintf("https://%s%s", target.Target, target.Path)
         if !strings.HasPrefix(target.Path, "/") {
             url = fmt.Sprintf("https://%s/%s", target.Target, target.Path)
        }
    }


	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}

	if target.Host != "" {
		req.Host = target.Host
	}
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")
    req.Header.Set("Accept", "*/*")
    req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8")
    req.Header.Set("Connection", "close")


	client := &http.Client{
		Timeout: time.Duration(target.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Equivalent to CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST false
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

// checkTcp performs a TCP check
func checkTcp(target Target) bool {
	if target.Timeout <= 0 || target.Timeout > 3 {
		target.Timeout = 3
	}
	if target.Port == 0 {
		target.Port = 80 // Default port if not specified
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(target.Target, strconv.Itoa(target.Port)), time.Duration(target.Timeout)*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// checkPing performs a Ping check
func checkPing(target Target) bool {
	if target.Timeout <= 0 || target.Timeout > 2 {
		target.Timeout = 2 // Max timeout for ping
	}

    // If OS is Windows, or if exec is not available (not easily checkable in Go directly, assume available)
    // Fallback to TCP check if OS is Windows, as per PHP script
	if runtime.GOOS == "windows" {
        // The PHP script falls back to TCP check if exec is not available OR it's Windows.
        // For simplicity here, we'll assume if it's Windows, we do TCP check.
        // Port for ping isn't standard, but PHP script uses target.Port for TCP fallback.
        // This might not be what's intended for a 'ping' usually, but matches PHP.
        return checkTcp(Target{Target: target.Target, Port: target.Port, Timeout: target.Timeout})
    }

	cmd := exec.Command("ping", "-c", "1", "-w", strconv.Itoa(target.Timeout), target.Target)
	err := cmd.Run()
	return err == nil
}

// sendRequest utility function (similar to PHP's send_request)
func sendRequest(url string, jsonData []byte) ([]byte, error) {
    req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
    if err != nil {
        return nil, err
    }
    req.Header.Set("Content-Type", "application/json; charset=utf-8")
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")


    client := &http.Client{
        Timeout: 10 * time.Second, // Default timeout as in PHP
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    return body, nil
}


// nodeMonitorLocal performs a local check on a single target
func nodeMonitorLocal(nodeID string, t Target) MonitorResult {
	status := false
	switch t.Type {
	case "http":
		status = checkHttp(t)
	case "ping":
		status = checkPing(t)
	default: // tcp
		status = checkTcp(t)
	}
	successVal := 0
	if status {
		successVal = 1
	}
	return MonitorResult{NodeID: nodeID, Success: successVal, Target: t.Target}
}

// nodeMonitorRemote performs remote checks by calling a remote API
// configNode is the remote node definition from config, t is the list of targets for that remote node
func nodeMonitorRemote(nodeID string, apiURL string, targets []Target) []MonitorResult {
    results := []MonitorResult{}
    if len(targets) == 0 {
        return results
    }

    jsonPayload, err := json.Marshal(targets)
    if err != nil {
        // Cannot marshal targets, return empty results or log error
        return results
    }

    respData, err := sendRequest(apiURL, jsonPayload)
    if err != nil {
        // Request failed, return empty results or log error
        return results
    }

    var response struct {
        Msg []MonitorResult `json:"msg"`
    }
    if err := json.Unmarshal(respData, &response); err != nil {
        // Cannot unmarshal response, return empty or log
        return results
    }

    // Assign the nodeID from the config to the results from remote
    for i := range response.Msg { // Iterate by index to modify
        response.Msg[i].NodeID = nodeID // Override or set NodeID based on the current remote node's config
        results = append(results, response.Msg[i])
    }
    return results
}

// nodeMonitorAll orchestrates monitoring across all configured nodes and targets
// This will depend on the config structure (to be defined in step 5)
// For now, a placeholder or a simplified version based on direct input:
func nodeMonitorAll(targets []Target, appConfig *AppConfig) []MonitorResult {
    var results []MonitorResult
    targetGroup1 := []Target{}
    targetGroup2 := []Target{}

    for _, t := range targets {
        if t.NodeGroup == "2" {
            targetGroup2 = append(targetGroup2, t)
        } else {
            targetGroup1 = append(targetGroup1, t)
        }
    }

    // Process group 1
    if appConfig != nil && appConfig.Monitor.Group1 != nil && len(appConfig.Monitor.Group1) > 0 && len(targetGroup1) > 0 {
        for _, node := range appConfig.Monitor.Group1 {
            if node.Type == "local" {
                for _, t := range targetGroup1 {
                    results = append(results, nodeMonitorLocal(node.NodeID, t))
                }
            } else if node.Type == "remote" && node.Api != "" {
                results = append(results, nodeMonitorRemote(node.NodeID, node.Api, targetGroup1)...)
            }
        }
    }

    // Process group 2
    if appConfig != nil && appConfig.Monitor.Group2 != nil && len(appConfig.Monitor.Group2) > 0 && len(targetGroup2) > 0 {
        for _, node := range appConfig.Monitor.Group2 {
            if node.Type == "local" {
                for _, t := range targetGroup2 {
                    results = append(results, nodeMonitorLocal(node.NodeID, t))
                }
            } else if node.Type == "remote" && node.Api != "" {
                results = append(results, nodeMonitorRemote(node.NodeID, node.Api, targetGroup2)...)
            }
        }
    }
    return results
}
