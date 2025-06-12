package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// Helper function to setup router for tests
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New() // Use gin.New() for a clean router in tests
	// Add RecoveryMiddleware if testing panic scenarios, or other global middlewares
	router.Use(RecoveryMiddleware())

	router.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	// If testing static files, router.Static("/cdnfly", "./cdnfly") would be here
	// For this simple test, only /ping is needed.
	return router
}

func TestPingEndpoint(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ping", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Ping endpoint status code = %d, want %d", w.Code, http.StatusOK)
	}
	expectedBody := `{"message":"pong"}`
	if w.Body.String() != expectedBody {
		t.Errorf("Ping endpoint body = %s, want %s", w.Body.String(), expectedBody)
	}
}
