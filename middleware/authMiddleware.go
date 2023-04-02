package middleware

import (
	"net/http"

	"github.com/MayankSaxena03/JWTAuthentication/helpers"
	"github.com/gin-gonic/gin"
)

func Authenticate() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientToken := c.Request.Header.Get("token")
		if clientToken == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token not provided"})
			c.Abort()
			return
		}

		claims, err := helpers.ValidateToken(clientToken)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		c.Set("_id", claims.Id)
		c.Set("email", claims.Email)
		c.Set("username", claims.Username)
		c.Set("userType", claims.UserType)
	}
}
