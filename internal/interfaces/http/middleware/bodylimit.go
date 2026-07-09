package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultMaxRequestBodyBytes is the global cap on request body size. It is large
// enough for the biggest legitimate upload (branding images are separately
// capped at 2MB) while preventing an unbounded body from exhausting memory.
const DefaultMaxRequestBodyBytes int64 = 8 << 20 // 8MB

// BodyLimit wraps each request body with http.MaxBytesReader so that reading it
// (e.g. via ShouldBindJSON or multipart parsing) fails once maxBytes is
// exceeded, instead of buffering an arbitrarily large payload into memory.
// Handlers that need a stricter limit can still apply their own MaxBytesReader.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request != nil && c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		}
		c.Next()
	}
}
