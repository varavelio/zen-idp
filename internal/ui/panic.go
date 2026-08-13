package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// panicTitle is the document and page title of the user panic interaction.
const panicTitle = "Panic"

// panicAction is the form target of the panic confirmation form.
const panicAction = "/panic"

// PanicConfirmationPage renders the panic confirmation interaction: the
// product identity, a warning that the action ends every active session of
// the account and blocks sign-in, and a protected form whose submission
// triggers the panic. token is the anti-forgery token that protects the
// form submission.
func PanicConfirmationPage(settings config.UI, token string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, panicTitle,
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
					nodx.Class("space-y-2"),
					nodx.H1(nodx.Class("text-lg font-semibold text-content"), nodx.Text(name)),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text("Trigger the panic action?"),
					),
					nodx.P(
						nodx.Class("text-sm text-error"),
						nodx.Role("alert"),
						nodx.Text(
							"This ends every active session for your account and blocks "+
								"sign-in until an administrator clears the panic lock.",
						),
					),
				),
				nodx.FormEl(
					nodx.Action(panicAction),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					csrfField(token),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md bg-error text-base-100 font-medium py-2 px-3",
							"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-error",
						),
						nodx.Text("Trigger panic"),
					),
				),
			),
		),
	)
}

// PanicCompletePage renders the panic completion page: the product identity
// and a confirmation that the panic action was triggered, sign-in is
// blocked, and only an administrator can clear the lock.
func PanicCompletePage(settings config.UI) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, panicTitle,
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
						nodx.Text("The panic action was triggered."),
					),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text(
							"Your sessions were ended and sign-in is blocked. Ask an "+
								"administrator to clear the panic lock before signing in again.",
						),
					),
				),
			),
		),
	)
}

// PanicSessionRequiredPage renders the neutral page shown when a panic
// request does not carry a valid user session: the panic action requires an
// authenticated user, and the page reveals nothing about why access was
// denied.
func PanicSessionRequiredPage(settings config.UI) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, panicTitle,
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
						nodx.Text("Sign in is required to trigger the panic action."),
					),
				),
			),
		),
	)
}
