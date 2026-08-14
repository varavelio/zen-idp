package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/config"
)

// enrollTitle is the document and page title of the enrollment
// interaction.
const enrollTitle = "Enroll"

// enrollAction is the form target of the enrollment form.
const enrollAction = "/enroll"

// EnrollPage renders the enrollment interaction: it invites the user to
// reveal the QR code of their TOTP shared secret. token is the enrollment
// credential carried by the shared link, embedded in the form as a hidden
// field. csrfToken protects the form submission and failure is the
// optional generic denial message shown after a rejected redemption. The
// page itself never reveals enrollment material: the token is consumed
// only by the protected form submission.
func EnrollPage(settings config.UI, token, csrfToken, failure string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return page(settings, enrollTitle,
		standalonePage(settings, name, "Set up your authenticator app", "max-w-md",
			nodx.If(failure != "", errorAlert(failure)),
			nodx.FormEl(
				nodx.Action(enrollAction),
				nodx.Method("post"),
				nodx.Class("space-y-5"),
				csrfField(csrfToken),
				nodx.Input(
					nodx.Attr("type", "hidden"),
					nodx.Name("token"),
					nodx.Value(token),
				),
				actionButton(buttonPrimary, "Show QR", lucide.QrCode(nodx.Class("size-4"))),
			),
			nodx.P(
				nodx.Class("text-xs text-content-muted text-center"),
				nodx.Text("The code is revealed only once"),
			),
		),
	)
}

// identifier is one sign-in identifier of the enrolled user with its
// optional label.
type identifier struct {
	value string
	label string
}

// identifierBox renders the sign-in identifiers of the enrolled user: the
// subject and, when configured, the additional login identifier, with a
// note that sign-in uses one of them together with the code from the
// authenticator app.
func identifierBox(subject, login string) nodx.Node {
	identifiers := []identifier{{value: subject}}
	note := "Use this identifier together with the 6-digit code from your authenticator app to sign in."
	if login != "" && login != subject {
		identifiers = append(identifiers, identifier{value: login, label: "login"})
		identifiers[0].label = "sub"
		note = "Use either identifier together with the 6-digit code from your authenticator app to sign in."
	}
	return nodx.Div(
		nodx.Class("space-y-2 rounded-lg border border-base-400 bg-base-100 p-4"),
		nodx.P(
			nodx.Class("flex items-center gap-1.5 text-sm font-medium text-content"),
			lucide.User(nodx.Class("size-4 text-content-muted")),
			nodx.Text("Sign in with"),
		),
		nodx.Div(
			nodx.Class("space-y-1.5"),
			nodx.Map(identifiers, func(item identifier) nodx.Node {
				return nodx.Div(
					nodx.Class(
						"flex items-center justify-between gap-2 rounded-md",
						"border border-base-400 bg-base-200 px-3 py-2",
					),
					nodx.SpanEl(
						nodx.Class("min-w-0 truncate font-mono text-sm text-content"),
						nodx.Text(item.value),
					),
					nodx.If(
						item.label != "",
						nodx.SpanEl(
							nodx.Class("shrink-0 text-xs text-content-muted"),
							nodx.Text(item.label),
						),
					),
				)
			}),
		),
		nodx.P(nodx.Class("text-xs text-content-muted"), nodx.Text(note)),
	)
}

// EnrollmentReadyPage renders the one-time reveal of a completed
// enrollment: the QR code of the otpauth URI, the sign-in identifiers, and
// the manual entry values. login is the user's additional login
// identifier, equal to subject when none is configured. The page must
// never be cached.
func EnrollmentReadyPage(
	settings config.UI,
	subject, login, otpauthURI, secret, qrDataURI string,
) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return page(settings, enrollTitle,
		standalonePage(settings, name, "Scan the code with your authenticator app", "max-w-md",
			nodx.Div(
				nodx.Class("mx-auto w-fit rounded-lg bg-white p-3"),
				nodx.Img(
					nodx.Class("h-52 w-52"),
					nodx.Src(qrDataURI),
					nodx.Alt("TOTP enrollment QR code"),
				),
			),
			identifierBox(subject, login),
			labeledCodeBlock("Account: "+subject, otpauthURI),
			labeledCodeBlock("Or enter this code manually:", secret),
			nodx.Div(
				nodx.Class(
					"flex items-start gap-2 rounded-md border border-warning/25",
					"bg-warning/10 p-3 text-sm text-warning",
				),
				nodx.Role("alert"),
				lucide.TriangleAlert(nodx.Class("mt-0.5 size-4 shrink-0")),
				nodx.P(nodx.Text("This will not be shown again.")),
			),
		),
	)
}
