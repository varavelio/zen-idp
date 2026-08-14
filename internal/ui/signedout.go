package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/config"
)

// signedOutTitle is the document and page title of the local logout
// interaction.
const signedOutTitle = "Signed out"

// signOutTitle is the document and page title of the sign-out confirmation
// interaction.
const signOutTitle = "Sign out"

// LoggedOutPage renders the local logout completion page: the product
// identity and a confirmation that this browser is no longer signed in.
func LoggedOutPage(settings config.UI) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, signedOutTitle,
		standalonePage(settings, name, "You have been signed out.", "max-w-sm",
			nodx.Div(
				nodx.Class(
					"flex items-start gap-2 rounded-md border border-success/25",
					"bg-success/10 p-3 text-sm text-success",
				),
				lucide.BadgeCheck(nodx.Class("mt-0.5 size-4 shrink-0")),
				nodx.P(
					nodx.Text("This browser is no longer signed in."),
				),
			),
		),
	)
}

// LogOutConfirmationPage renders the sign-out confirmation interaction: the
// product identity and a protected form whose submission completes the
// local logout. token is the anti-forgery token that protects the form
// submission and action is the form target, which carries the original
// logout request when it requests a post-logout redirect.
func LogOutConfirmationPage(settings config.UI, token, action string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, signOutTitle,
		standalonePage(settings, name, "End your session on this device?", "max-w-sm",
			nodx.FormEl(
				nodx.Action(action),
				nodx.Method("post"),
				nodx.Class("space-y-5"),
				csrfField(token),
				actionButton(buttonPrimary, "Sign out", lucide.LogOut(nodx.Class("size-4"))),
			),
		),
	)
}
