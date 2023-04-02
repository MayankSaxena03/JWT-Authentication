package controllers

import (
	"context"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/MayankSaxena03/JWTAuthentication/database"
	"github.com/MayankSaxena03/JWTAuthentication/helpers"
	"github.com/MayankSaxena03/JWTAuthentication/models"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var userCollection = database.OpenCollection(database.Client, "users")
var validate = validator.New()

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var user models.User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err = validate.Struct(user)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		user.Password, err = HashPassword(user.Password)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		emailExist, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if emailExist > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User with this email already exists"})
			return
		}
		phoneExist, err := userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if phoneExist > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User with this phone already exists"})
			return
		}

		user.CreatedOn = time.Now()
		user.UpdatedOn = time.Now()

		token, refreshToken, err := helpers.GenerateAllTokens(user.ID.Hex(), user.Email, user.Username, user.UserType)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.Token = token
		user.RefreshToken = refreshToken

		result, err := userCollection.InsertOne(ctx, user)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		user.ID = result.InsertedID.(primitive.ObjectID)
		c.JSON(http.StatusOK, gin.H{"User inserted at ID": user.ID})
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		err := c.ShouldBindJSON(&user)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		var foundUser models.User
		err = userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})
				return
			}
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		err = VerifyPassword(foundUser.Password, user.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token, refreshToken, err := helpers.GenerateAllTokens(foundUser.ID.Hex(), foundUser.Email, foundUser.Username, foundUser.UserType)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		err = helpers.UpdateAllTokens(foundUser.ID, token, refreshToken)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": token, "refreshToken": refreshToken})
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		userType := c.GetString("userType")
		if userType != "Admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}

		l := c.Query("limit")
		if l == "" {
			l = "10"
		}
		limit, err := strconv.Atoi(l)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit"})
			return
		}
		s := c.Query("s")
		if s == "" {
			s = "0"
		}
		skip, err := strconv.Atoi(s)
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid skip"})
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var users []models.User
		cursor, err := userCollection.Find(ctx, bson.M{}, options.Find().SetLimit(int64(limit)).SetSkip(int64(skip)))
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer cursor.Close(ctx)
		for cursor.Next(ctx) {
			var user models.User
			cursor.Decode(&user)
			users = append(users, user)
		}
		if err := cursor.Err(); err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": users})
	}
}

func GetUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, err := primitive.ObjectIDFromHex(c.Param("id"))
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		id := c.GetString("_id")
		userType := c.GetString("userType")
		if id != userID.Hex() && userType != "Admin" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		user, err := helpers.GetUserFromID(userID)
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"data": user})
	}
}
