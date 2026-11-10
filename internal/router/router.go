package router

import (
	"UserManagementSystem/internal/handler"
	"UserManagementSystem/internal/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func New(health *handler.HealthHandler) *gin.Engine {

	gin.SetMode(gin.ReleaseMode)

	r := gin.New()

	_ = r.SetTrustedProxies(nil)

	r.Use(middleware.RequestID())
	r.Use(middleware.Logger())
	r.Use(middleware.Recovery())

	r.GET("/healthz", health.Healthz)
	r.GET("/readyz", health.Readyz)
	r.GET("/slow", func(c *gin.Context) {
		time.Sleep(3 * time.Second)
		c.JSON(200, gin.H{
			"slow": "done",
		})
	})

	return r
}
