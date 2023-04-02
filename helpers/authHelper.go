package helpers

import (
	"context"
	"time"

	"github.com/MayankSaxena03/JWTAuthentication/database"
	"github.com/MayankSaxena03/JWTAuthentication/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

var userCollection = database.OpenCollection(database.Client, "users")

func GetUserFromID(id primitive.ObjectID) (models.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	var user models.User
	query := bson.M{
		"_id": id,
	}
	err := userCollection.FindOne(ctx, query).Decode(&user)
	return user, err
}
