package auth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/rngallen/medium/pkg/seed"
	"golang.org/x/crypto/bcrypt"
)

var Store *session.Store

func login(c *fiber.Ctx) error {
	// Used to help prevent timing attacks
	emptyHash, err := bcrypt.GenerateFromPassword([]byte(""), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	emptyHashString := string(emptyHash)

	// Retrieve the submitted form data
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Check if the credentials are valid
	user, exists := seed.Users[username]
	var checkPassword string
	if exists {
		checkPassword = user.Password
	} else {
		checkPassword = emptyHashString
	}

	if bcrypt.CompareHashAndPassword([]byte(checkPassword), []byte(password)) != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"err": "invalid credentials"})
	}

	// Set a session variable to mark the user as logged in
	session, err := Store.Get(c)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	if err := session.Reset(); err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	session.Set("loggedIn", true)
	if err := session.Save(); err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	// Redirect to the protected route
	// return c.Redirect("/test/protected") // <= will return a new csrf token which will be valid
	return c.SendStatus(fiber.StatusOK) //<= will not return a new csrf token
}

func logout(c *fiber.Ctx) error {
	// Retrieve the session
	session, err := Store.Get(c)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Revoke users authentication
	if err := session.Destroy(); err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Redirect to the login page
	return c.Status(fiber.StatusOK).SendString("logout successfully")
}

func protected(c *fiber.Ctx) error {
	switch c.Method() {
	case "POST":
		// Retrieve the submitted form data
		message := c.FormValue("message")
		return c.Status(fiber.StatusOK).SendString(message)
	default:
		return c.Status(fiber.StatusOK).SendString("hello")
	}

}

func home(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).SendString("welcome home")
}

func Routes(router fiber.Router) {
	router.Post("/login", login)
	router.Get("/home", home)
	router.Post("/logout", logout)

}

func RoutesProtected(router fiber.Router) {
	router.Get("/protected", protected)
	router.Post("/protected", protected)
}
