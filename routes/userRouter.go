package routes

import (
	"github.com/MayankSaxena03/JWTAuthentication/controllers"
	"github.com/MayankSaxena03/JWTAuthentication/middleware"
	"github.com/gin-gonic/gin"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("/users/:id", controllers.GetUser())
}
