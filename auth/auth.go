package auth

import (
	"cloud-storage/db_access"
	slogext "cloud-storage/utils/slogExt"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthData struct {
	db              db_access.DbAccess
	tokenKey        []byte
	tokenTimeToLive time.Duration
}

const hMACKeySize = 32

type Claims struct {
	UserId int64 `json:"user_id"`
	jwt.RegisteredClaims
}

func NewAuthData(db db_access.DbAccess, tokenTTL time.Duration) *AuthData {
	key := make([]byte, hMACKeySize)
	rand.Read(key)
	return &AuthData{
		db:       db,
		tokenKey: key,
		tokenTimeToLive: tokenTTL,
	}
}

type AuthCtx string

const AuthUserId AuthCtx = "auth user id"

func Auth(a *AuthData) func(http.Handler) http.Handler {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			const op = "auth.Auth"
			log := slogext.LogWithOp(op, r.Context())

			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				errorMsg := "No Authorization header provided"
				log.Error(errorMsg)

				if err := writeError(w, NoSessionToken, errorMsg, http.StatusUnauthorized); err != nil {
					log.Error("Could not write response", slogext.Error(err))
				}
				return
			}

			sessionTokenData := strings.Split(authHeader, " ")
			if len(sessionTokenData) != 2 || sessionTokenData[0] != "Bearer" {
				errorMsg := "Invalid authorization scheme"
				log.Error(errorMsg)

				if err := writeError(w, InvalidSessionToken, errorMsg, http.StatusUnauthorized); err != nil {
					log.Error("Could not write response", slogext.Error(err))
				}
				return
			}

			token, err := jwt.ParseWithClaims(
				sessionTokenData[1],
				&Claims{},
				func(t *jwt.Token) (any, error) {
					return a.tokenKey, nil
				},
				jwt.WithExpirationRequired(),
				jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
			)
			if err != nil {
				errorMsg := "Invalid session token"
				log.Error(errorMsg, slogext.Error(err))

				if err := writeError(w, InvalidSessionToken, errorMsg, http.StatusUnauthorized); err != nil {
					log.Error("Could not write response", slogext.Error(err))
				}
				return
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				errorMsg := "Invalid session token"
				log.Error(errorMsg, slogext.Error(errors.New("Invalid Claims type")))

				if err := writeError(w, InvalidSessionToken, errorMsg, http.StatusUnauthorized); err != nil {
					log.Error("Could not write response", slogext.Error(err))
				}
				return
			}

			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthUserId, claims.UserId)))
		})
	}
}

func UserId(ctx context.Context) (userId int64) {
	userId, ok := ctx.Value(AuthUserId).(int64)
	if !ok {
		userId = -1
	}
	return
}

func Register(a *AuthData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "auth.Register"
		log := slogext.LogWithOp(op, r.Context())

		decoder := json.NewDecoder(r.Body)
		var req AuthRequest
		if err := decoder.Decode(&req); err != nil {
			errorMsg := "Invalid json"
			log.Error(errorMsg, slogext.Error(err))

			if err := writeError(w, InvalidContentFormat, errorMsg, http.StatusBadRequest); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			errorMsg := "Bad password"
			log.Error(errorMsg, slogext.Error(err))

			if err := writeError(w, InvalidCredentials, errorMsg, http.StatusUnprocessableEntity); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		user := db_access.User{
			Name:         req.Name,
			PasswordHash: hash,
		}
		var uce db_access.UniqueConstraintError
		if err := a.db.AddUser(&user); errors.As(err, &uce) {
			errorMsg := "Name already used"
			log.Error(errorMsg)

			if err := writeError(w, InvalidCredentials, errorMsg, http.StatusConflict); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		} else if err != nil {
			errorMsg := "Database error"
			log.Error(errorMsg, slogext.Error(err))

			if err := writeError(w, InternalApiError, "", http.StatusServiceUnavailable); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		log.Info("Registered new user", slog.String("name", user.Name))
		w.WriteHeader(http.StatusNoContent)
	}
}

func Login(a *AuthData) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "auth.Login"
		log := slogext.LogWithOp(op, r.Context())

		decoder := json.NewDecoder(r.Body)

		var req AuthRequest
		if err := decoder.Decode(&req); err != nil {
			errorMsg := "Invalid json"
			log.Error(errorMsg, slogext.Error(err))

			if err := writeError(w, InvalidContentFormat, errorMsg, http.StatusBadRequest); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		var user db_access.User
		user.Name = req.Name

		var nre db_access.NoRowsError
		if err := a.db.GetUser(&user); errors.As(err, &nre) {
			errorMsg := "Invalid credentials"
			log.Error(errorMsg)

			if err := writeError(w, InvalidCredentials, errorMsg, http.StatusUnauthorized); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		} else if err != nil {
			log.Error("Database error", slogext.Error(err))

			if err := writeError(w, InternalApiError, "", http.StatusServiceUnavailable); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(req.Password)); err != nil {
			errorMsg := "Invalid credentials"
			log.Error(errorMsg, slogext.Error(err))

			if err := writeError(w, InvalidCredentials, errorMsg, http.StatusUnauthorized); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		now := time.Now()
		claims := Claims{
			user.Id,
			jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(now),
				ExpiresAt: jwt.NewNumericDate(now.Add(a.tokenTimeToLive)),
			},
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.tokenKey)
		if err != nil {
			log.Error("JWT creation error", slogext.Error(err))

			if err := writeError(w, InternalApiError, "", http.StatusServiceUnavailable); err != nil {
				log.Error("Could not write response", slogext.Error(err))
			}
			return
		}

		resp := AuthResponse{
			SessionToken: token,
		}
		if err := resp.write(w, http.StatusOK); err != nil {
			log.Error("Could not write response", slogext.Error(err))
		}
	}
}
