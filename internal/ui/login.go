package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/config"
)

// loginTitle is the document and page title of the login interaction, also
// used as the product name when none is configured.
const loginTitle = "Sign in"

// LoginPage renders the sign-in interaction: the product identity, the
// identifier and one-time-code fields, and an optional failure message.
// action is the form target that carries the pending authorization request
// parameters, which are forwarded unchanged when the form is submitted.
// csrfToken protects the form submission from cross-site request forgery.
func LoginPage(settings config.UI, action, csrfToken, failure string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return page(settings, loginTitle,
		standalonePage(settings, name, "Sign in with your one-time code", "max-w-md",
			nodx.If(failure != "", errorAlert(failure)),
			nodx.FormEl(
				nodx.Action(action),
				nodx.Method("post"),
				nodx.Class("space-y-5"),
				csrfField(csrfToken),
				textInput(
					"identifier", "identifier", "Login identifier", "username", "text",
					lucide.User(nodx.Class("size-4")),
					nodx.Placeholder("Your identifier"),
					nodx.Required(true),
					nodx.Autofocus(true),
				),
				textInput(
					"code", "code", "One-time code", "one-time-code", "password",
					lucide.KeyRound(nodx.Class("size-4")),
					nodx.Required(true),
					nodx.Placeholder("XXX XXX"),
					nodx.Attr("inputmode", "numeric"),
					nodx.Attr("pattern", "[0-9]{6}"),
					nodx.Maxlength("6"),
					nodx.Minlength("6"),
				),
				actionButton(buttonPrimary, loginTitle, lucide.LogIn(nodx.Class("size-4"))),
			),
		),
	)
}

// InvalidRequestPage renders the generic page shown when a request cannot
// be processed because no trusted target exists for an error redirect.
func InvalidRequestPage() nodx.Node {
	return noticePage(
		"Zen IdP",
		"Invalid authorization request",
		"The authorization request could not be processed.",
	)
}
