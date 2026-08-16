package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/totp"
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
				warningAlert(
					"Before you continue, make sure no one is watching your screen. "+
						"If you are in a virtual meeting or sharing your screen, be careful: "+
						"anyone who sees this code could scan it and access your account.",
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
// enrollment: the QR code, the sign-in identifiers, and the manual entry
// values. login is the user's additional login identifier, equal to
// subject when none is configured. name is the human-readable
// authenticator account name shown for manual configuration. The page
// must never be cached.
func EnrollmentReadyPage(
	settings config.UI,
	subject, login, secret, qrDataURI, name string,
) nodx.Node {
	productName := settings.Name
	if productName == "" {
		productName = loginTitle
	}
	return page(
		settings,
		enrollTitle,
		standalonePage(
			settings,
			productName,
			"Scan the code with your authenticator app",
			"max-w-md",
			nodx.Div(
				nodx.Class("mx-auto w-fit rounded-lg bg-white p-3"),
				nodx.Img(
					nodx.Class("h-52 w-52"),
					nodx.Src(qrDataURI),
					nodx.Alt("TOTP enrollment QR code"),
				),
			),
			identifierBox(subject, login),
			manualEntryBox(secret, name),
			warningAlert("This will not be shown again."),
		),
	)
}

// manualEntryRow renders one labeled value of the manual entry card with
// its copy button. Overlong values wrap onto several lines instead of
// truncating, so the full value is always visible.
func manualEntryRow(label, value string) nodx.Node {
	return nodx.Div(
		nodx.Class(
			"flex items-center justify-between gap-2 rounded-md",
			"border border-base-400 bg-base-200 px-3 py-2",
		),
		nodx.Div(
			nodx.Class("min-w-0"),
			nodx.P(nodx.Class("text-xs text-content-muted"), nodx.Text(label)),
			nodx.P(
				nodx.Class("break-all font-mono text-sm text-content"),
				nodx.Text(value),
			),
		),
		copyButton(value),
	)
}

// manualEntryBox renders the values needed to configure the authenticator
// app manually instead of scanning the QR code: the shared secret and the
// account profile values. Every value mirrors exactly what the QR code
// encodes, so manual entry provisions the same account as scanning, and
// every value has a copy button.
func manualEntryBox(secret, name string) nodx.Node {
	return nodx.Div(
		nodx.Class("space-y-2 rounded-lg border border-base-400 bg-base-100 p-4"),
		nodx.P(
			nodx.Class("flex items-center gap-1.5 text-sm font-medium text-content"),
			lucide.KeyRound(nodx.Class("size-4 text-content-muted")),
			nodx.Text("Or configure manually"),
		),
		nodx.Div(
			nodx.Class("space-y-1.5"),
			manualEntryRow("Secret", secret),
			manualEntryRow("Name", name),
			manualEntryRow("Algorithm", totp.ProfileAlgorithm),
			manualEntryRow("Digits", totp.ProfileDigits),
			manualEntryRow("Period", totp.ProfilePeriod),
		),
	)
}
