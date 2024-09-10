package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var (
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	dynoDB    *dynamodb.DynamoDB
)

func init() {
	// Initialize a session that the SDK will use to load
	// credentials from the shared credentials file ~/.aws/credentials
	// and region from the shared configuration file ~/.aws/config.
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	dynoDB = dynamodb.New(sess)
}

type User struct {
	Email       string `json:"Email"`
	Password    string `json:"Password"`
	Description string `json:"Description"`
}

type Claims struct {
	Email       string `json:"Email"`
	Fingerprint string `json:"fingerprint"`
	jwt.StandardClaims
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Println(request.Body)

	var user User
	err := json.Unmarshal([]byte(request.Body), &user)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: err.Error()}, nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error hashing password"}, nil
	}

	user.Password = string(hashedPassword)

	inputValue, err := dynamodbattribute.MarshalMap(user)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error marshalling user data"}, nil
	}

	input := &dynamodb.PutItemInput{
		Item:      inputValue,
		TableName: aws.String("Auth"),
	}

	_, err = dynoDB.PutItem(input)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error saving user to database"}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 201,
		Body:       `{"message": "User registered successfully"}`,
	}, nil
}

func main() {
	lambda.Start(handler)
}
