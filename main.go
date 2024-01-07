package main

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/log"
	"github.com/gofiber/fiber/v2/middleware/csrf"
	"github.com/gofiber/fiber/v2/middleware/encryptcookie"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"
	"github.com/rngallen/medium/pkg/auth"
	"github.com/rngallen/medium/pkg/routes"
	"github.com/rngallen/medium/pkg/seed"
)

func main() {

	// In production, run the app on port 443 with TLS enabled
	// or run the app behind a reverse proxy that handles TLS.
	//
	// It is also recommended that the csrf cookie is set to be
	// Secure and HttpOnly and have the SameSite attribute set
	// to Lax or Strict.
	//
	// In this example, we use the "__Host-" prefix for cookie names.
	// This is suggested when your app uses secure connections (TLS).
	// A cookie with this prefix is only accepted if it's secure,
	// comes from a secure source, doesn't have a Domain attribute,
	// and its Path attribute is "/".
	// This makes these cookies "locked" to the domain.
	//
	// See the following for more details:
	// https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
	//
	// It's recommended to use the "github.com/gofiber/fiber/v2/middleware/helmet"
	// middleware to set headers to help prevent attacks such as XSS, man-in-the-middle,
	// protocol downgrade, cookie hijacking, SSL stripping, clickjacking, etc.

	// Never hardcode passwords in production code

	// HTML templates
	engine := html.New("./views", ".html")

	// Create a Fiber app
	app := fiber.New(fiber.Config{
		Views:       engine,
		ViewsLayout: "layouts/main",
	})

	seed.Seed()
	// Recover from panic
	app.Use(recover.New())
	// Helmet Middleware
	app.Use(helmet.New())

	app.Use(encryptcookie.New(encryptcookie.Config{
		Except: []string{csrf.ConfigDefault.CookieName},
		Key:    encryptcookie.GenerateKey(),
	}))

	auth.Store = session.New(session.Config{
		Expiration:     30 * time.Minute, // Expire sessions after 30 minutes of inactivity
		KeyLookup:      "cookie:session", // Recommended to use the __Host- prefix when serving the app over TLS
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: "Strict",
	})

	// csrfMiddleware := csrf.New(csrfConfig)

	app.Use(csrf.New(csrf.Config{
		Session:    auth.Store,
		KeyLookup:  "header:" + csrf.HeaderName, // In this example, we will be using a hidden input field to store the CSRF token
		CookieName: csrf.ConfigDefault.CookieName,
		// CookieName:     "__Host-csrf", // Recommended to use the __Host- prefix when serving the app over TLS
		CookieSameSite: "Lax", // Recommended to set this to Lax or Strict
		CookieSecure:   false, // Recommended to set to true when serving the app over TLS
		CookieHTTPOnly: true,  // Recommended, otherwise if using JS framework recomend: false and KeyLookup: "header:X-CSRF-Token"
		ErrorHandler:   csrfErrorHandler,
		Expiration:     30 * time.Minute},
	))

	routes.SetupRoutes(app)
	log.Fatal(app.Listen(":3031"))
}

func csrfErrorHandler(c *fiber.Ctx, err error) error {
	// Log the error so we can track who is trying to perform CSRF attacks
	// customize this to your needs
	log.Warnf("CSRF Error: %v Request: %v From: %v\n", err, c.OriginalURL(), c.IP())

	// check accepted content types
	switch c.Accepts("html", "json") {
	case "json":
		// Return a 403 Forbidden response for JSON requests
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "403 Forbidden",
		})
	case "html":
		// Return a 403 Forbidden response for HTML requests
		return c.Status(fiber.StatusForbidden).Render("error", fiber.Map{
			"Title":     "Error",
			"Error":     "403 Forbidden",
			"ErrorCode": "403",
		})
	default:
		// Return a 403 Forbidden response for all other requests
		return c.Status(fiber.StatusForbidden).SendString("403 Forbidden")
	}
}
