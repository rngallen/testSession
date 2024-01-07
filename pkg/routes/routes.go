package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/rngallen/medium/pkg/auth"
)

func SetupRoutes(app *fiber.App) {

	auth.Routes(app)

	test := app.Group("test", authMiddleware)
	auth.RoutesProtected(test)

}

func authMiddleware(c *fiber.Ctx) error {
	session, err := auth.Store.Get(c)
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}
	loggedIn, _ := session.Get("loggedIn").(bool)

	if !loggedIn {
		// User is not authenticated, redirect to the login page
		return c.SendStatus(fiber.StatusUnauthorized)
	}
	return c.Next()
}
