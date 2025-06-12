package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// RecoveryMiddleware catches panics and returns a JSON 500 error.
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v", err) // Log the panic
				// Optionally, log stack trace: debug.PrintStack()
				if !c.Writer.Written() { // Check if response has already been sent
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
				}
			}
		}()
		c.Next() // Process request
	}
}

func main() {
	// Load configuration
	_, err := LoadConfig("app_config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err) // Already good logging here
	}

	router := gin.Default()

	// Apply the recovery middleware globally
	router.Use(RecoveryMiddleware())

	// Serve static files from the ./cdnfly directory
	router.Static("/cdnfly", "./cdnfly")

	// Ping endpoint
	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})

	// Register new handlers
	router.GET("/common/datetime", commonDatetimeHandler)
	// PHP was GET, but seems more like a POST if it's "upgrading" something, though it reads a file. Let's stick to POST as per index.php $method=='GET' for /master/upgrades it was GET.
	// Correcting the /master/upgrades to GET as per original PHP
	router.GET("/master/upgrades", masterUpgradesHandler)

	router.POST("/common/timestamp", commonTimestampHandler)
	router.POST("/common/timestamp2", commonTimestamp2Handler)
	router.POST("/auth", authHandler)
	router.POST("/auth2", auth2Handler)
	router.POST("/check", checkHandler) // Added /check route
	router.POST("/api/monitorlocal", apiMonitorLocalHandler) // Added new route
	router.POST("/admin/updateversion", updateVersionHandler) // Added new route

	log.Println("Starting server on port 6688") // Added server start log
	err = router.Run(":6688") // Changed from just router.Run for error handling
	if err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
