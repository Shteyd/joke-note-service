package main

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	// -- Initialization
	type configModel struct {
		IsDebug     bool   `mapstructure:"DEBUG"`
		PostgresDsn string `mapstructure:"POSTGRES_DSN"`
		HttpPort    string `mapstructure:"HTTP_PORT"`

		SigningKey   string `mapstructure:"SIGNING_KEY"`
		PasswordSalt string `mapstructure:"PASSWORD_SALT"`
	}

	var config *configModel
	{
		currentDir, err := os.Getwd()
		if err != nil {
			panic(err.Error())
		}

		viper.SetConfigFile(currentDir + "/.env")
		viper.AutomaticEnv()

		if err := viper.ReadInConfig(); err != nil {
			panic(err.Error())
		}

		if err := viper.Unmarshal(&config); err != nil {
			panic(err.Error())
		}

		viper.WatchConfig()
	}

	var database *pg.DB
	{
		orm.SetTableNameInflector(func(s string) string {
			return s
		})

		opt, err := pg.ParseURL(config.PostgresDsn)
		if err != nil {
			panic(err.Error())
		}

		database = pg.Connect(opt)
	}
	defer database.Close()

	logrus.SetFormatter(&logrus.JSONFormatter{})

	// -- Models --
	type userRequest struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	type customer struct {
		Id           int    `pg:"type:INTEGER"`
		Email        string `pg:"type:VARCHAR(255)"`
		PasswordHash string `pg:"type:VARCHAR(255)"`
	}

	type noteRequest struct {
		Title       string `json:"title" binding:"required"`
		Description string `json:"description" binding:"omitempty"`
	}

	type updateNoteRequest struct {
		Title       string `json:"title" binding:"omitempty"`
		Description string `json:"description" binding:"omitempty"`
	}

	type noteResponce struct {
		Id          int    `json:"id"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}

	type note struct {
		Id          int    `pg:"type:INTEGER"`
		CustomerId  int    `pg:"type:INTEGER"`
		Title       string `pg:"type:VARCHAR(255)"`
		Description string `pg:"type:TEXT"`
	}

	// -- Migrations
	if _, err := database.Exec(`
	CREATE TABLE IF NOT EXISTS "customer" (
		"id" INTEGER GENERATED ALWAYS AS IDENTITY,
		"email" VARCHAR(255) NOT NULL,
		"password_hash" VARCHAR(255) NOT NULL,

		PRIMARY KEY ("id")
	);

	CREATE TABLE IF NOT EXISTS "note" (
		"id" INTEGER GENERATED ALWAYS AS IDENTITY,
		"customer_id" INTEGER NOT NULL,
		"title" VARCHAR(255) NOT NULL,
		"description" TEXT,

		PRIMARY KEY ("id"),
		FOREIGN KEY ("customer_id") REFERENCES "customer" ("id")
	);
	`); err != nil {
		panic(err.Error())
	}

	// -- Delivery --
	httpServer := gin.Default()
	if !config.IsDebug {
		gin.SetMode(gin.ReleaseMode)
	}

	// -- Api router group --
	api := httpServer.Group("/api")
	{
		// Claims for jwt
		type tokenClaims struct {
			jwt.StandardClaims
			UserId int `json:"user_id"`
		}

		api.GET("/ping", func(ctx *gin.Context) {
			ctx.JSON(http.StatusOK, gin.H{"status": "ok", "data": "pong"})
		})

		// -- Authorization router group --
		userGroup := api.Group("/auth")
		{
			// Generate password with sha1 crypt
			generatePassword := func(password string) string {
				hash := sha1.New()
				hash.Write([]byte(password))
				return fmt.Sprintf("%x", hash.Sum([]byte(config.PasswordSalt)))
			}

			// Sign in route
			userGroup.POST("/sign-in", func(ctx *gin.Context) {
				var request userRequest
				if err := ctx.ShouldBindJSON(&request); err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				model := customer{
					Email:        request.Email,
					PasswordHash: generatePassword(request.Password),
				}

				// Get user by email/pass from db
				err := database.
					Model(&model).
					Where("email = ?email").
					Where("password_hash = ?password_hash").
					Select()
				if err != nil {
					logrus.Error("get user from database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
				}

				// Generate token
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, &tokenClaims{
					jwt.StandardClaims{
						ExpiresAt: time.Now().Add(12 * time.Hour).Unix(),
						IssuedAt:  time.Now().Unix(),
					},
					model.Id,
				})

				jwtToken, err := token.SignedString([]byte(config.SigningKey))
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok", "token": jwtToken})
			})

			// Sign up
			userGroup.POST("/sign-up", func(ctx *gin.Context) {
				var request userRequest
				if err := ctx.ShouldBindJSON(&request); err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				model := customer{
					Email:        request.Email,
					PasswordHash: generatePassword(request.Password),
				}

				// Create user in db
				_, err := database.
					Model(&model).
					Returning("id").
					Insert()
				if err != nil {
					logrus.Error("create user in database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok", "id": model.Id})
			})
		}

		noteGroup := api.Group("/note")
		{
			// -- Auth middleware --

			// User identification
			getUserId := func(ctx *gin.Context) (int, error) {
				id, ok := ctx.Get("userId")
				if !ok {
					return 0, errors.New("user id not found")
				}

				validId, ok := id.(int)
				if !ok {
					return 0, errors.New("user id is of invalid type")
				}

				return validId, nil
			}

			// Middleware usage
			noteGroup.Use(func(ctx *gin.Context) {
				// Check headers and parse
				authHeader := ctx.GetHeader("Authorization")
				if authHeader == "" {
					logrus.Info("Empty auth header: ", authHeader)
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, "Empty auth header")
					return
				}

				// Parse token
				token, err := jwt.ParseWithClaims(authHeader, &tokenClaims{}, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, errors.New("invalid signing error")
					}

					return []byte(config.SigningKey), nil
				})
				if err != nil {
					logrus.Error("parse token error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, err)
					return
				}

				claims, ok := token.Claims.(*tokenClaims)
				if !ok {
					err := errors.New("token claims are not of type *tokenClaims")
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, err)
					return
				}

				ctx.Set("userId", claims.UserId)
			})

			// Create note
			noteGroup.POST("/", func(ctx *gin.Context) {
				userId, err := getUserId(ctx)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
					return
				}

				var request noteRequest
				if err := ctx.ShouldBindJSON(&request); err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				// Create note in db
				model := note{
					CustomerId:  userId,
					Title:       request.Title,
					Description: request.Description,
				}

				_, err = database.
					Model(&model).
					ExcludeColumn("id").
					Returning("*").
					Insert()
				if err != nil {
					logrus.Error("create note in database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok", "data": noteResponce{
					Id:          model.Id,
					Title:       model.Title,
					Description: model.Description,
				}})
			})

			// Get notes
			noteGroup.GET("/", func(ctx *gin.Context) {
				userId, err := getUserId(ctx)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
					return
				}

				// Get user notes from db
				var models []note
				err = database.
					Model(&models).
					Where("customer_id = ?", userId).
					Select()
				if err != nil {
					logrus.Error("delete notes from database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				var notes []noteResponce
				for _, model := range models {
					notes = append(notes, noteResponce{
						Id:          model.Id,
						Title:       model.Title,
						Description: model.Description,
					})
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok", "data": notes})
			})

			// Get note
			noteGroup.GET("/:id", func(ctx *gin.Context) {
				userId, err := getUserId(ctx)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
					return
				}

				noteId, err := strconv.Atoi(ctx.Param("id"))
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				// Get user note from db
				model := note{Id: noteId, CustomerId: userId}
				err = database.
					Model(&model).
					Where("id = ?id").
					Where("customer_id = ?customer_id").
					Select()
				if err != nil {
					logrus.Error("get note from database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok", "data": noteResponce{
					Id:          model.Id,
					Title:       model.Title,
					Description: model.Description,
				}})
			})

			// Update note
			noteGroup.PATCH("/:id", func(ctx *gin.Context) {
				userId, err := getUserId(ctx)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
					return
				}

				noteId, err := strconv.Atoi(ctx.Param("id"))
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				var request updateNoteRequest
				if err := ctx.ShouldBindJSON(&request); err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				// Update note in db
				_, err = database.
					Model(&note{
						Id:          noteId,
						CustomerId:  userId,
						Title:       request.Title,
						Description: request.Description,
					}).
					Where("id = ?id").
					Where("customer_id = ?customer_id").
					UpdateNotZero()
				if err != nil {
					logrus.Error("update note in database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
			})

			// Delete note
			noteGroup.DELETE("/:id", func(ctx *gin.Context) {
				userId, err := getUserId(ctx)
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
					return
				}

				noteId, err := strconv.Atoi(ctx.Param("id"))
				if err != nil {
					ctx.AbortWithStatusJSON(http.StatusBadRequest, err.Error())
					return
				}

				// Delete note from db
				_, err = database.
					Model(&note{Id: noteId, CustomerId: userId}).
					Where("id = ?id").
					Where("customer_id = ?customer_id").
					Delete()
				if err != nil {
					logrus.Error("delete note from database error", err)
					ctx.AbortWithStatusJSON(http.StatusInternalServerError, errors.New("database error"))
					return
				}

				ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
			})
		}
	}

	httpServer.Run(config.HttpPort)
}
