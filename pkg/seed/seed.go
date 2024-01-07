package seed

import (
	"github.com/gofiber/fiber/v2/log"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user in the dummy authentication system
type User struct {
	Username string
	Password string
}

// Dummy user database
var Users = make(map[string]User)

func Seed() {
	hashedPasswords := make(map[string]string)
	for username, password := range map[string]string{"user1": "password1", "user2": "password2"} {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Fatal(err)
		}
		hashedPasswords[username] = string(hashedPassword)
	}

	for username, hashedPassword := range hashedPasswords {
		Users[username] = User{Username: username, Password: hashedPassword}
	}
}
