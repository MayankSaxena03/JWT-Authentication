package helpers

import (
	"context"
	"fmt"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type SignedDetails struct {
	Id       string
	Email    string
	Username string
	UserType string
	jwt.StandardClaims
}

var SECRET_KEY = os.Getenv("SECRET_KEY")

func GenerateAllTokens(id, email, username, userType string) (string, string, error) {
	claims := SignedDetails{
		Id:       id,
		Email:    email,
		Username: username,
		UserType: userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 1).Unix(),
		},
	}

	refreshClaims := SignedDetails{
		Id:       id,
		Email:    email,
		Username: username,
		UserType: userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 24).Unix(),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err
	}

	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString([]byte(SECRET_KEY))
	return token, refreshToken, err
}

func UpdateAllTokens(userId primitive.ObjectID, signedToken, signedRefreshToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	query := bson.M{
		"_id": userId,
	}
	update := bson.M{
		"$set": bson.M{
			"token":        signedToken,
			"refreshToken": signedRefreshToken,
			"updatedOn":    time.Now(),
		},
	}

	return userCollection.FindOneAndUpdate(ctx, query, update).Err()
}

func ValidateToken(signedToken string) (claims *SignedDetails, err error) {
	token, err := jwt.ParseWithClaims(
		signedToken,
		&SignedDetails{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(SECRET_KEY), nil
		},
	)
	if err != nil {
		return
	}

	claims, ok := token.Claims.(*SignedDetails)
	if !ok {
		err = fmt.Errorf("Invalid token")
		return
	}

	if claims.ExpiresAt < time.Now().Local().Unix() {
		err = fmt.Errorf("Token expired")
		return
	}

	return
}
