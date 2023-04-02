package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	Username     string             `json:"username,omitempty" bson:"username,omitempty"`
	Password     string             `json:"password,omitempty" bson:"password,omitempty" validate:"required,min=8"`
	Email        string             `json:"email,omitempty" bson:"email,omitempty" validate:"required,email"`
	Phone        string             `json:"phone,omitempty" bson:"phone,omitempty" validate:"required,numeric"`
	Token        string             `json:"token,omitempty" bson:"token,omitempty"`
	UserType     string             `json:"userType,omitempty" bson:"userType,omitempty" validate:"required,eq=Admin|eq=User"`
	RefreshToken string             `json:"refreshToken,omitempty" bson:"refreshToken,omitempty"`
	CreatedOn    time.Time          `json:"createdOn,omitempty" bson:"createdOn,omitempty"`
	UpdatedOn    time.Time          `json:"updatedOn,omitempty" bson:"updatedOn,omitempty"`
}
