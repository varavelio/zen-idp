package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// signedOutTitle is the document and page title of the local logout
// interaction.
const signedOutTitle = "Signed out"

// signOutTitle is the document and page title of the sign-out confirmation
// interaction.
const signOutTitle = "Sign out"

// signOutAction is the form target of the sign-out confirmation form.
const signOutAction = "/logout"

// LoggedOutPage renders the local logout completion page: the product
// identity and a confirmation that this browser is no longer signed in.
func LoggedOutPage(settings config.UI) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, signedOutTitle,
		nodx.Main(
			nodx.Class("min-h-screen flex items-center justify-center px-4"),
			nodx.Div(
				nodx.Class(
					"w-full max-w-sm bg-base-200 border border-base-400 rounded-lg p-8 space-y-6",
				),
				nodx.If(
					settings.LogoURL != "",
					nodx.Img(nodx.Class("h-10 w-auto"), nodx.Src(settings.LogoURL), nodx.Alt("")),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.H1(nodx.Class("text-lg font-semibold text-content"), nodx.Text(name)),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text("You have been signed out."),
					),
				),
			),
		),
	)
}

// LogOutConfirmationPage renders the sign-out confirmation interaction: the
// product identity and a protected form whose submission completes the local
// logout. token is the anti-forgery token that protects the form submission.
func LogOutConfirmationPage(settings config.UI, token string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, signOutTitle,
		nodx.Main(
			nodx.Class("min-h-screen flex items-center justify-center px-4"),
			nodx.Div(
				nodx.Class(
					"w-full max-w-sm bg-base-200 border border-base-400 rounded-lg p-8 space-y-6",
				),
				nodx.If(
					settings.LogoURL != "",
					nodx.Img(nodx.Class("h-10 w-auto"), nodx.Src(settings.LogoURL), nodx.Alt("")),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.H1(nodx.Class("text-lg font-semibold text-content"), nodx.Text(name)),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text("End your session on this device?"),
					),
				),
				nodx.FormEl(
					nodx.Action(signOutAction),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					csrfField(token),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md bg-content text-base-100 font-medium py-2 px-3 "+
								"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Text("Sign out"),
					),
				),
			),
		),
	)
}
