package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Email       string `json:"Email"`
	Fingerprint string `json:"fingerprint"`
	jwt.RegisteredClaims
}

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {

	cookieHeader := request.Headers["Cookie"]

	tokenHeader := request.Headers["Authorization"]

	if cookieHeader == "" || tokenHeader == "" {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: "Missing header"}, nil
	}
	jwtToken := strings.TrimPrefix(tokenHeader, "Bearer ")
	fmt.Println(cookieHeader)

	cookieValue, err := getCookie(request, "fingerprint")

	hash := sha256.Sum256([]byte(cookieValue))
	var cookieFingerprint = base64.StdEncoding.EncodeToString(hash[:])

	claims := &Claims{}

	token, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
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
	var greeting string
	sourceIP := request.RequestContext.Identity.SourceIP
	fmt.Println(request)

	if sourceIP == "" {
		greeting = "Hello, world!\n"
	} else {
		greeting = fmt.Sprintf("Hello, %s!\n", sourceIP)
	}

	return events.APIGatewayProxyResponse{
		Body:       greeting,
		StatusCode: 200,
	}, nil
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
