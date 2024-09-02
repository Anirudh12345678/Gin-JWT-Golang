package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Anirudh12345678/GoLangBackend/models"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	host     = "127.0.0.1"
	port     = 5432
	user     = "postgres"
	password = "123"
	database = "drizzle_db"
)

type userPg struct {
	Username string
	Password string
}

func main() {
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  "user=postgres password=123 dbname=drizzle_db port=5432 sslmode=disable TimeZone=Asia/Shanghai",
		PreferSimpleProtocol: true,
	}), &gorm.Config{})
	if err != nil {
		log.Fatalln(err)
	}
	// var user userPg
	// // var users []userPg
	// db.Table("auth_user").Take(&user)
	// fmt.Println(user)
	r := gin.Default()
	r.POST("/login", jwtLoginMiddleware(db), func(c *gin.Context) {
		v := c.MustGet("token")
		c.JSON(200, gin.H{"token": v})
	})
	r.GET("/access", accessMiddleWare(), func(ctx *gin.Context) {

	})
	r.Run()
}

var sampleSecretKey = []byte("AppleMango")

func createToken(username string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["username"] = username
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func accessMiddleWare() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(400, gin.H{"error": "no headers"})
			return
		}
		tokenString = tokenString[len("Bearer "):]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return sampleSecretKey, nil
		})
		if err != nil {
			c.JSON(400, gin.H{"error": "cant parse"})
			return
		}
		if !token.Valid {
			c.JSON(400, gin.H{"error": "invalid token!"})
			return
		}
		c.JSON(200, gin.H{"status": "authorized"})
		c.Next()
	}
}
func jwtLoginMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user userPg
		var input models.LoginInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		token, err := createToken(input.Username)
		if err != nil {
			fmt.Println("not created token")
			return
		}
		db.Table("auth_user").Where("username = ?", input.Username).Take(&user)
		fmt.Println(user.Password)
		error := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password))
		fmt.Println(error)
		if error != nil {
			c.Set("token", "Invalid Login")
			c.Next()
		}
		c.Set("token", token)
		c.Next()

	}
}
