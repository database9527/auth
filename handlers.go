package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	aesKeyConst    = "L6DYHZ3NEb2QUL6D" // AES_KEY
	aesKey2Const   = "kQ3vaLGnZ8sgyd5T" // AES_KEY2
	keyAppendConst = "rbkgp46j53"       // KEY_APPEND
)

// Helper function to pad data to AES block size
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := make([]byte, padding)
	for i := range padtext {
		padtext[i] = byte(padding)
	}
	return append(data, padtext...)
}

// Helper function to unpad data after AES decryption
func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("pkcs7Unpad: input data is empty")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("pkcs7Unpad: invalid padding size")
	}
	return data[:(length - unpadding)], nil
}

// textEncrypt replicates PHP's text_encrypt
func textEncrypt(data string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plaintext := []byte(data)
	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)

	ciphertext := make([]byte, len(paddedPlaintext))
	iv := key[:aes.BlockSize] // In the PHP code, key is used as IV

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	return hex.EncodeToString(ciphertext), nil
}

// textDecrypt replicates PHP's text_decrypt
func textDecrypt(encryptedDataHex string, key []byte) (string, error) {
	encryptedData, err := hex.DecodeString(encryptedDataHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(encryptedData) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := key[:aes.BlockSize] // In the PHP code, key is used as IV
	decrypted := make([]byte, len(encryptedData))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedData)

	unpaddedData, err := pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}

	return string(unpaddedData), nil
}

// getAesKey replicates PHP's get_aes_key
func getAesKey(keyParam string) []byte {
	hash := md5.Sum([]byte(keyParam + keyAppendConst))
	return []byte(hex.EncodeToString(hash[:])[:16])
}

// parseInput replicates PHP's parse_input
// Expects JSON input: {"rnd": "some_random_string"}
func parseInput(c *gin.Context) (map[string]interface{}, error) {
	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	decryptedText, err := textDecrypt(string(body), []byte(aesKeyConst))
	if err != nil {
		return nil, err
	}
	var params map[string]interface{}
	err = json.Unmarshal([]byte(decryptedText), &params)
	if err != nil {
		return nil, err
	}
	return params, nil
}

// parseInput2 replicates PHP's parse_input2
// Expects JSON input: {"rnd": "some_random_string", "machine_code": "code"}
func parseInput2(c *gin.Context) (map[string]interface{}, error) {
    body, err := ioutil.ReadAll(c.Request.Body)
    if err != nil {
        return nil, err
    }
    keyParam := c.Query("key")
    if keyParam == "" {
        return nil, fmt.Errorf("key query parameter is missing")
    }
    dynamicKey := getAesKey(keyParam)
    decryptedText, err := textDecrypt(string(body), dynamicKey)
    if err != nil {
        return nil, err
    }
    var params map[string]interface{}
    err = json.Unmarshal([]byte(decryptedText), &params)
    if err != nil {
        return nil, err
    }
    return params, nil
}

// generateOutput replicates PHP's generate_output
func generateOutput(c *gin.Context, data map[string]interface{}) {
	jsonData, _ := json.Marshal(data)
	encryptedData, err := textEncrypt(string(jsonData), []byte(aesKeyConst))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt data"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": encryptedData, "msg": ""})
}

// generateOutput2 replicates PHP's generate_output2
func generateOutput2(c *gin.Context, data map[string]interface{}) {
    keyParam := c.Query("key")
    if keyParam == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "key query parameter is missing"})
        return
    }
    dynamicKey := getAesKey(keyParam)
    jsonData, _ := json.Marshal(data)
    encryptedData, err := textEncrypt(string(jsonData), dynamicKey)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt data"})
        return
    }
    c.JSON(http.StatusOK, gin.H{"code": 0, "data": encryptedData, "msg": ""})
}


// Handler for /common/datetime
func commonDatetimeHandler(c *gin.Context) {
	c.String(http.StatusOK, time.Now().Format("2006-01-02 15:04:05"))
}

// Handler for /master/upgrades
func masterUpgradesHandler(c *gin.Context) {
	versionData, err := ioutil.ReadFile("version.json")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": -1,
			"data": []string{},
			"ip":   c.ClientIP(),
			"msg":  "版本信息文件不存在",
		})
		return
	}

	var versionInfo interface{}
	err = json.Unmarshal(versionData, &versionInfo)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"code": -1,
			"data": []string{},
			"ip":   c.ClientIP(),
			"msg":  "解析版本信息文件失败",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":  0,
		"count": 1,
		"data":  []interface{}{versionInfo},
		"ip":    c.ClientIP(),
	})
}

// Handler for /common/timestamp
func commonTimestampHandler(c *gin.Context) {
    params, err := parseInput(c)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
        return
    }
    rnd, ok := params["rnd"]
    if !ok {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'rnd' in input"})
        return
    }
    data := gin.H{
        "now": time.Now().Unix(),
        "rnd": rnd,
    }
    generateOutput(c, data)
}

// Handler for /common/timestamp2
func commonTimestamp2Handler(c *gin.Context) {
    params, err := parseInput2(c)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
        return
    }
    rnd, ok := params["rnd"]
    if !ok {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'rnd' in input"})
        return
    }
    data := gin.H{
        "now": time.Now().Unix(),
        "rnd": rnd,
    }
    generateOutput2(c, data)
}

// apiMonitorLocalHandler processes requests similar to the original api.php
func apiMonitorLocalHandler(c *gin.Context) {
	var targets []Target // Using the same Target struct from monitor.go
	if err := c.ShouldBindJSON(&targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON input: " + err.Error()})
		return
	}

	var results []MonitorResult
	// api.php implies these are all local checks for a single, implicit node.
	// We'll use a predefined node_id for these direct API calls.
	const localApiNodeID = "local_direct_api"

	for _, target := range targets {
		// node_monitor_local from monitor.php takes node_id and target.
		// The PHP api.php calls node_monitor_local('1', $target);
		// We'll use our constant for clarity.
		result := nodeMonitorLocal(localApiNodeID, target)
		results = append(results, result)
	}

	c.JSON(http.StatusOK, gin.H{"msg": results})
}

// updateVersionHandler fetches version info and saves it to version.json
func updateVersionHandler(c *gin.Context) {
	updateURL := "https://update.cdnfly.cn/master/upgrades?version_num=" // As per update.php

	// Use sendRequest from monitor.go or define a similar local one if preferred for different timeout/settings
	// For this task, we'll use a standard http.Client
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // Match PHP's SSL settings
		},
	}

	resp, err := client.Get(updateURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch version info: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read version info response: " + err.Error()})
		return
	}

	var updateResponse struct {
		Code int           `json:"code"`
		Data []interface{} `json:"data"` // Assuming data is an array of objects
		Msg  string        `json:"msg"`
	}

	if err := json.Unmarshal(body, &updateResponse); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse version info JSON: " + err.Error(), "raw_response": string(body)})
		return
	}

	if updateResponse.Code != 0 || len(updateResponse.Data) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get valid version data", "details": updateResponse.Msg, "raw_response": string(body)})
		return
	}

	// Extract the first element of the data array, as in PHP
	versionInfoToSave := updateResponse.Data[0]
	versionJSON, err := json.MarshalIndent(versionInfoToSave, "", "  ") // Pretty print JSON
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to marshal version info for saving: " + err.Error()})
		return
	}

	err = ioutil.WriteFile("version.json", versionJSON, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save version info to version.json: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "保存cdnfly版本信息成功！"})
}

// Placeholder for /check endpoint
// Updated checkHandler for /check endpoint
func checkHandler(c *gin.Context) {
	var targets []Target // Define Target struct if not already accessible, or ensure monitor.go is part of the same package
	if err := c.ShouldBindJSON(&targets); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON input: " + err.Error()})
		return
	}

	if globalAppConfig == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Configuration not loaded"})
		return
	}

	results := nodeMonitorAll(targets, globalAppConfig)
	c.JSON(http.StatusOK, gin.H{"msg": results})
}

// Handler for /auth
func authHandler(c *gin.Context) {
    params, err := parseInput(c)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
        return
    }
    machineCode, ok := params["machine_code"]
    if !ok {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'machine_code' in input"})
        return
    }
    data := gin.H{
        "nodes":        10000,
        "machine_code": machineCode,
        "end_at":       time.Now().Unix() + 3600*24*365, // PHP: time()+3600*24*365
    }
    generateOutput(c, data)
}

// Handler for /auth2
func auth2Handler(c *gin.Context) {
    params, err := parseInput2(c)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
        return
    }
    machineCode, ok := params["machine_code"]
    if !ok {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Missing 'machine_code' in input"})
        return
    }
    data := gin.H{
        "nodes":        10000,
        "machine_code": machineCode,
        "end_at":       time.Now().Unix() + 3600*24*3650, // PHP: time()+3600*24*3650
    }
    generateOutput2(c, data)
}
