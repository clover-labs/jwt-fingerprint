package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/golang-jwt/jwt/v5"
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
	jwt.Claims
}
type loginData struct {
	Email    string `json:"Email"`
	Password string `json:"Password"`
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	fmt.Println(request.Body)

	var loginData loginData

	err := json.Unmarshal([]byte(request.Body), &loginData)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: err.Error()}, nil
	}

	user, err := getUserFromDB(loginData.Email)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 401, Body: "Invalid credentials"}, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 401, Body: "Invalid credentials"}, nil
	}

	fingerprint := generateFingerprint(request)
	token, err := generateToken(user.Email, fingerprint)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error generating token"}, nil
	}
	response, _ := json.Marshal(map[string]string{
		"token": token,
	})
	//cookieValue := base64.StdEncoding.EncodeToString([]byte(fingerprint))
	expires := time.Now().Add(24 * time.Hour).UTC().Format(http.TimeFormat)
	userAgent := request.Headers["User-Agent"]
	sourceIP := request.RequestContext.Identity.SourceIP
	// You might want to add more unique identifiers here

	fingerprintData := userAgent + sourceIP
	cookieString := fmt.Sprintf("fingerprint=%s; HttpOnly; Secure; SameSite=Strict; Expires=%s", fingerprintData, expires)

	return events.APIGatewayProxyResponse{
		StatusCode: 201,
		Body:       string(response),
		Headers: map[string]string{
			"Set-Cookie":   cookieString,
			"Content-Type": "application/json",
		},
	}, nil
}
func generateFingerprint(request events.APIGatewayProxyRequest) string {
	userAgent := request.Headers["User-Agent"]
	sourceIP := request.RequestContext.Identity.SourceIP
	// You might want to add more unique identifiers here

	fingerprintData := userAgent + sourceIP
	hash := sha256.Sum256([]byte(fingerprintData))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func generateToken(email, fingerprint string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":       email,
		"fingerprint": fingerprint,
		"iat":         time.Now().Unix(),
		"exp":         time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	})
	return token.SignedString(jwtSecret)
}
func getUserFromDB(email string) (*User, error) {
	result, err := dynoDB.GetItem(&dynamodb.GetItemInput{
		TableName: aws.String("Auth"),
		Key: map[string]*dynamodb.AttributeValue{
			"Email": {
				S: aws.String(email),
			},
		},
	})

	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return nil, fmt.Errorf("user not found")
	}

	var user User
	err = dynamodbattribute.UnmarshalMap(result.Item, &user)
	if err != nil {
		return nil, err
	}

	return &user, nil
}
func main() {
	lambda.Start(handler)
}
