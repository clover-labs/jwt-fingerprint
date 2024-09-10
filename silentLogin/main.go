package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/golang-jwt/jwt/v5"
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
	jwt.RegisteredClaims
}

var silentLoginData struct {
	Token string `json:"token"`
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	cookieHeader := request.Headers["Cookie"]
	if cookieHeader == "" {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Missing header"}, nil
	}

	fmt.Println(cookieHeader)

	err := json.Unmarshal([]byte(request.Body), &silentLoginData)
	if err != nil {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: err.Error()}, nil
	}

	cookieValue, err := getCookie(request, "fingerprint")

	hash := sha256.Sum256([]byte(cookieValue))
	var cookieFingerprint = base64.StdEncoding.EncodeToString(hash[:])

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(silentLoginData.Token, claims, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		hmacSampleSecret := []byte(os.Getenv("JWT_SECRET"))
		return hmacSampleSecret, nil
	})

	if err != nil {
		fmt.Println("Error parsing token:", err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: err.Error()}, nil
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {

		// Check if token is expired
		if claims.ExpiresAt != nil {
			if time.Now().Unix() > claims.ExpiresAt.Unix() {
				fmt.Println("Token is expired.")
			} else {
				fmt.Println("Token is not expired.")
			}
		} else {
			return events.APIGatewayProxyResponse{StatusCode: 500, Body: "exp missing"}, nil
		}
	} else {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "invalid claims"}, nil
	}

	if cookieFingerprint != claims.Fingerprint {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "invalid fingerprint"}, nil
	}

	if err != nil || !token.Valid {
		fmt.Println(err)
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error"}, nil
	}

	fingerprint := generateFingerprint(request)
	responseToken, err := generateToken(claims.Email, fingerprint)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Error generating token"}, nil
	}
	response, _ := json.Marshal(map[string]string{
		"token": responseToken,
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

func getCookie(request events.APIGatewayProxyRequest, name string) (string, error) {
	cookieHeader := request.Headers["Cookie"]
	if cookieHeader == "" {
		return "", fmt.Errorf("no cookies found")
	}

	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		parts := strings.Split(strings.TrimSpace(cookie), "=")
		if len(parts) == 2 && parts[0] == name {
			return parts[1], nil
		}
	}

	return "", fmt.Errorf("cookie %s not found", name)
}

func main() {
	lambda.Start(handler)
}
