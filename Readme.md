JWT Authentication Project using Golang

This is a sample project that demonstrates how to implement JSON Web Token (JWT) based authentication in a Golang application.
Project Structure

The project is structured as follows:

go

jwt-authentication-project/
  ├── main.go
  ├── routes/
  │   ├── authRouter.go
  │   └── userRouter.go
  ├── middleware/
  │   └── authMiddleware.go
  ├── database/
  │   └── databaseConnection.go
  ├── controllers/
  │   └── userController.go
  ├── helpers/
  │   ├── authHelper.go
  │   └── tokenHelper.go
  ├── models/
  │   └── user.go
  ├── Postman/
  │   └── JWT-Authentication.postman_collection.json
  ├── .env
  ├── go.mod
  └── go.sum

  JWT-Authentication.postman_collection.json

    main.go - The entry point of the application.
    routes/ - Contains the authentication-related code, including generating and validating JWT tokens.
    middleware/ - Contains the middleware code for authenticating HTTP requests.
    database/ - Contains the code for connecting to the database.
    controllers/ - Contains the controller code for handling HTTP requests.
    helpers/ - Contains the helper code for generating and validating JWT tokens.
    models/ - Contains the data models used in the application.
    go.mod and go.sum - Files that define the module and its dependencies.

Dependencies

The project depends on the following packages:

    github.com/dgrijalva/jwt-go - For generating and validating JWT tokens.
    github.com/gorilla/mux - For routing HTTP requests.
    golang.org/x/crypto/bcrypt - For hashing passwords.

Usage

To use this project, you need to have Golang and Postman installed on your machine.

    Clone the project to your machine.
    Install the project dependencies using the following command:

    go mod download


Start the server by running the following command:

    go run main.go

    Open Postman and import the provided collection located in the root of the project folder JWT-Authentication.postman_collection.json. This collection contains the following endpoints:
        Signup: POST /users/signup
        Login: POST /users/login
        Get All Users: GET /users
        Get User by ID: GET /users/{id}
    Note: The Get All Users and Get User by ID endpoints require authentication. To authenticate, send a request to the Login endpoint to obtain a JWT token, and then include that token in the headers of subsequent requests to the authenticated endpoints using the key token.
    Test the endpoints in Postman to create users, authenticate, and retrieve user information.