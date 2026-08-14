package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
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
	return page(settings, panicTitle,
		standalonePage(settings, name, "Trigger the panic action?", "max-w-sm",
			nodx.Div(
				nodx.Class(
					"flex flex-col items-center gap-3 rounded-lg border border-error/25",
					"bg-error/10 p-6 text-center",
				),
				lucide.TriangleAlert(nodx.Class("size-10 text-error")),
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
				actionButton(
					buttonDanger,
					"Trigger panic",
					lucide.TriangleAlert(nodx.Class("size-4")),
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
	return page(settings, panicTitle,
		standalonePage(settings, name, "The panic action was triggered.", "max-w-sm",
			nodx.Div(
				nodx.Class(
					"flex items-start gap-2 rounded-md border border-success/25",
					"bg-success/10 p-3 text-sm text-success",
				),
				lucide.BadgeCheck(nodx.Class("mt-0.5 size-4 shrink-0")),
				nodx.P(
					nodx.Text(
						"Your sessions were ended and sign-in is blocked. Ask an "+
							"administrator to clear the panic lock before signing in again.",
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
	return page(
		settings,
		panicTitle,
		standalonePage(
			settings,
			name,
			"Sign in is required to trigger the panic action.",
			"max-w-sm",
			nodx.Div(
				nodx.Class(
					"flex items-start gap-2 rounded-md border border-base-400",
					"bg-base-100 p-3 text-sm text-content-muted",
				),
				lucide.ShieldAlert(nodx.Class("mt-0.5 size-4 shrink-0")),
				nodx.P(
					nodx.Text(
						"Sign in with your identifier and one-time code first, then "+
							"return to the panic action.",
					),
				),
			),
		),
	)
}
