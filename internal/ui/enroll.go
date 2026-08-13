package ui

import (
	"fmt"

	nodx "github.com/varavelio/nodxgo"
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
	return Page(settings, enrollTitle,
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
						nodx.Text("Set up your authenticator app."),
					),
				),
				nodx.If(
					failure != "",
					nodx.P(
						nodx.Class("text-sm text-error"),
						nodx.Role("alert"),
						nodx.Text(failure),
					),
				),
				nodx.FormEl(
					nodx.Action(enrollAction),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					csrfField(csrfToken),
					nodx.If(
						token != "",
						nodx.Input(
							nodx.Attr("type", "hidden"),
							nodx.Name("token"),
							nodx.Value(token),
						),
					),
					nodx.If(
						token == "",
						nodx.Div(
							nodx.Class("space-y-2"),
							nodx.LabelEl(
								nodx.Attr("for", "token"),
								nodx.Class("block text-sm font-medium text-content"),
								nodx.Text("Enrollment token"),
							),
							nodx.Input(
								nodx.Attr("type", "text"),
								nodx.Name("token"),
								nodx.Id("token"),
								nodx.Autocomplete("off"),
								nodx.Required(true),
								nodx.Autofocus(true),
								nodx.Class(
									"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm",
									"text-content placeholder:text-content-muted focus:outline-none",
									"focus:ring-2 focus:ring-content",
								),
							),
						),
					),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md bg-content text-base-100 font-medium py-2 px-3",
							"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Text("Show QR"),
					),
				),
				nodx.P(
					nodx.Class("text-xs text-content-muted"),
					nodx.Text("The code is revealed only once, after this step."),
				),
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
	return Page(settings, enrollTitle,
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
						nodx.Text("Scan the code with your authenticator app."),
					),
				),
				nodx.Img(
					nodx.Class("mx-auto h-52 w-52"),
					nodx.Src(qrDataURI),
					nodx.Alt("TOTP enrollment QR code"),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm text-content"),
						nodx.Text(fmt.Sprintf("Account: %s", subject)),
					),
					nodx.CodeEl(
						nodx.Class(
							"block break-all rounded-md border border-base-400 bg-base-100",
							"px-3 py-2 text-xs text-content select-all",
						),
						nodx.Text(otpauthURI),
					),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text("Or enter this code manually:"),
					),
					nodx.CodeEl(
						nodx.Class(
							"block break-all rounded-md border border-base-400 bg-base-100",
							"px-3 py-2 text-xs text-content select-all",
						),
						nodx.Text(secret),
					),
				),
				nodx.P(
					nodx.Class("text-sm text-warning"),
					nodx.Role("alert"),
					nodx.Text("Copy this code now. It will not be shown again."),
				),
				nodx.P(
					nodx.Class("text-sm text-content-muted"),
					nodx.Text(
						"You can now sign in with your identifier and the code from your authenticator.",
					),
				),
			),
		),
	)
}
