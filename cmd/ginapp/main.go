package ginapp

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Item struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Price float64 `json:"price"`
}

type ItemRequest struct {
	Name  string  `json:"name"  binding:"required,min=2,max=50"`
	Price float64 `json:"price" binding:"required,gt=0"`
}

func respondErr(c *gin.Context, status int, code, msg string) {
	c.JSON(status, gin.H{
		"error": gin.H{
			"code":    code,
			"message": msg,
		},
	})
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		c.Set("request_id", id)
		c.Header("X-Request-ID", id)
		c.Next()
	}
}

func timingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next() // run everything below, then return here
		dur := time.Since(start)
		fmt.Printf("req %s %s %s %d %s\n",
			c.GetString("request_id"),
			c.Request.Method,
			c.FullPath(), // route TEMPLATE (/api/v1/items/:id), not raw path
			c.Writer.Status(),
			dur.Round(time.Microsecond),
		)
	}
}

func blocker() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("X-Block") == "1" {
			respondErr(c, http.StatusForbidden, "blocked", "blocked")
			c.Abort()
			return
		}
		c.Next()
	}
}

func main() {
	// gin.New() gives us an EMPTY router. We deliberately do NOT use
	// gin.Default() because it silently installs Gin's own Logger + Recovery
	// in an order we cannot control.
	r := gin.New()

	// ---- Exercise 8: custom recovery ----
	r.Use(gin.CustomRecovery(func(c *gin.Context, recovered any) {
		// Log the panic, never return the panic string to the client.
		log.Printf("panic recovered (request_id=%s): %v", c.GetString("request_id"), recovered)
		respondErr(c, http.StatusInternalServerError, "internal", "internal error")
		c.Abort()
	}))

	// ---- Exercise 10: wiring order ----
	r.Use(requestIDMiddleware())
	r.Use(timingMiddleware())

	// ---- Exercise 1: /ping ----
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"pong": true,
			"ts":   time.Now().UTC().Format(time.RFC3339),
		})
	})

	
	r.GET("/search", func(c *gin.Context) {
		q := c.Query("q")
		limitStr := c.DefaultQuery("limit", "10")
		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit < 1 || limit > 100 {
			respondErr(c, http.StatusBadRequest, "invalid_query", "limit must be a positive integer <= 100")
			return
		}
		c.JSON(http.StatusOK, gin.H{"q": q, "limit": limit})
	})

	r.GET("/boom", func(c *gin.Context) {
		panic("kaboom")
	})

	api := r.Group("/api/v1")

	// Hardcoded dataset for this exercise.
	items := []Item{
		{ID: "1", Name: "Widget", Price: 9.99},
		{ID: "2", Name: "Gadget", Price: 19.99},
	}

	// ---- Exercise 2: GET /items ----
	api.GET("/items", func(c *gin.Context) {
		c.JSON(http.StatusOK, items)
	})

	// ---- Exercise 2: GET /items/:id ----
	api.GET("/items/:id", func(c *gin.Context) {
		id := c.Param("id")
		for _, it := range items {
			if it.ID == id {
				c.JSON(http.StatusOK, it)
				return
			}
		}
		respondErr(c, http.StatusNotFound, "not_found", "item not found")
	})

	// ---- Exercise 4 + 7: POST /items with binding + blocker ----
	// blocker() is registered on THIS ROUTE ONLY (route-level middleware).
	api.POST("/items", blocker(), func(c *gin.Context) {
		fmt.Println("handler ran") // must NOT print when X-Block: 1

		var req ItemRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			// 422 for binding/validation failure. We do NOT leak the
			// raw validator error string.
			respondErr(c, http.StatusUnprocessableEntity, "invalid_input", "invalid input")
			return
		}

		out := Item{ID: uuid.NewString(), Name: req.Name, Price: req.Price}
		c.JSON(http.StatusCreated, gin.H{
			"item":       out,
			"request_id": c.GetString("request_id"),
		})
	})

	addr := ":8081"
	log.Printf("listening on %s", addr)
	if err := r.Run(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}