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
// field; when empty, the form asks the user to paste the token delivered
// by the operator instead. csrfToken protects the form submission and
// failure is the optional generic denial message shown after a rejected
// redemption. The page itself never reveals enrollment material: the token
// is consumed only by the protected form submission.
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

// EnrollmentReadyPage renders the one-time reveal of a completed
// enrollment: the QR code of the otpauth URI and the manual entry values.
// The page must never be cached.
func EnrollmentReadyPage(
	settings config.UI,
	subject, otpauthURI, secret, qrDataURI string,
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
			nodx.P(
				nodx.Class("text-sm text-content-muted"),
				nodx.Text(
					"You can now sign in with your identifier and the code from your authenticator.",
				),
			),
		),
	)
}
