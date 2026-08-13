package ui

import (
	"fmt"

	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
)

// adminTitle is the document and page title of the administration
// interaction, also used as the product name when none is configured.
const adminTitle = "Administration"

// enrollmentTokenTitle is the document and page title of the one-time
// enrollment-token display.
const enrollmentTokenTitle = "Enrollment token"

// adminLoginAction is the form target of the administrator sign-in form.
const adminLoginAction = "/admin/login"

// adminLogoutAction is the form target of the administrator sign-out form.
const adminLogoutAction = "/admin/logout"

// adminTokensAction is the form target of the enrollment-token creation
// form.
const adminTokensAction = "/admin/tokens"

// adminHomePath is the administration landing page, the destination of the
// link shown after an enrollment token is created.
const adminHomePath = "/admin"

// csrfField renders the hidden anti-forgery field that every
// state-changing administration form must carry.
func csrfField(token string) nodx.Node {
	return nodx.Input(
		nodx.Attr("type", "hidden"),
		nodx.Name(csrf.FieldName),
		nodx.Value(token),
	)
}

// AdminLoginPage renders the administrator sign-in interaction: the product
// identity, a password field, and an optional failure message. token is the
// anti-forgery token that protects the form submission.
func AdminLoginPage(settings config.UI, token, failure string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return Page(settings, adminTitle,
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
						nodx.Text("Administrator sign-in"),
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
					nodx.Action(adminLoginAction),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					csrfField(token),
					nodx.Div(
						nodx.Class("space-y-2"),
						nodx.LabelEl(
							nodx.Attr("for", "password"),
							nodx.Class("block text-sm font-medium text-content"),
							nodx.Text("Administrator password"),
						),
						nodx.Input(
							nodx.Attr("type", "password"),
							nodx.Name("password"),
							nodx.Id("password"),
							nodx.Autocomplete("current-password"),
							nodx.Required(true),
							nodx.Autofocus(true),
							nodx.Class(
								"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm",
								"text-content placeholder:text-content-muted focus:outline-none",
								"focus:ring-2 focus:ring-content",
							),
						),
					),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md bg-content text-base-100 font-medium py-2 px-3",
							"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Text("Sign in"),
					),
				),
			),
		),
	)
}

// AdminHomePage renders the administration landing page shown to an
// authenticated administrator: the enrollment-token creation form and the
// protected sign-out form. token is the anti-forgery token that protects
// the form submissions; failure is an optional message shown when the last
// enrollment-token creation was rejected.
func AdminHomePage(settings config.UI, token, failure string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return Page(settings, adminTitle,
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
						nodx.Text("Signed in as administrator."),
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
				nodx.Div(
					nodx.Class("space-y-5"),
					nodx.H2(
						nodx.Class("text-sm font-semibold text-content"),
						nodx.Text("Create enrollment token"),
					),
					nodx.FormEl(
						nodx.Action(adminTokensAction),
						nodx.Method("post"),
						nodx.Class("space-y-5"),
						csrfField(token),
						nodx.Div(
							nodx.Class("space-y-2"),
							nodx.LabelEl(
								nodx.Attr("for", "subject"),
								nodx.Class("block text-sm font-medium text-content"),
								nodx.Text("Subject"),
							),
							nodx.Input(
								nodx.Attr("type", "text"),
								nodx.Name("subject"),
								nodx.Id("subject"),
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
						nodx.Div(
							nodx.Class("space-y-2"),
							nodx.LabelEl(
								nodx.Attr("for", "duration"),
								nodx.Class("block text-sm font-medium text-content"),
								nodx.Text("Duration"),
							),
							nodx.Input(
								nodx.Attr("type", "text"),
								nodx.Name("duration"),
								nodx.Id("duration"),
								nodx.Autocomplete("off"),
								nodx.Placeholder("e.g. 30m, 24h"),
								nodx.Class(
									"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm",
									"text-content placeholder:text-content-muted focus:outline-none",
									"focus:ring-2 focus:ring-content",
								),
							),
						),
						nodx.Div(
							nodx.Class("space-y-2"),
							nodx.LabelEl(
								nodx.Attr("for", "deadline"),
								nodx.Class("block text-sm font-medium text-content"),
								nodx.Text("Deadline"),
							),
							nodx.Input(
								nodx.Attr("type", "text"),
								nodx.Name("deadline"),
								nodx.Id("deadline"),
								nodx.Autocomplete("off"),
								nodx.Placeholder("e.g. 2026-01-02T15:04:05Z"),
								nodx.Class(
									"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm",
									"text-content placeholder:text-content-muted focus:outline-none",
									"focus:ring-2 focus:ring-content",
								),
							),
						),
						nodx.P(
							nodx.Class("text-xs text-content-muted"),
							nodx.Text(
								"Provide a relative duration or an absolute deadline; leave the other field empty.",
							),
						),
						nodx.Button(
							nodx.Attr("type", "submit"),
							nodx.Class(
								"w-full rounded-md bg-content text-base-100 font-medium py-2 px-3",
								"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
							),
							nodx.Text("Create enrollment token"),
						),
					),
				),
				nodx.FormEl(
					nodx.Action(adminLogoutAction),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					csrfField(token),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md border border-base-400 bg-base-100 text-content",
							"font-medium py-2 px-3 hover:opacity-90 focus:outline-none",
							"focus:ring-2 focus:ring-content",
						),
						nodx.Text("Sign out"),
					),
				),
			),
		),
	)
}

// EnrollmentTokenPage renders the one-time display of a freshly created
// enrollment token bound to the given subject and absolute expiration,
// together with the shareable enrollment link that carries the token. The
// token is shown exactly once on this page, which must never be cached.
func EnrollmentTokenPage(
	settings config.UI,
	subject, expiresAt, token, enrollURL string,
) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return Page(settings, enrollmentTokenTitle,
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
						nodx.Text("Enrollment token created."),
					),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm text-content"),
						nodx.Text(fmt.Sprintf("Subject: %s", subject)),
					),
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text(fmt.Sprintf("Expires: %s", expiresAt)),
					),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm text-content"),
						nodx.Text("Share this enrollment link with the user:"),
					),
					nodx.CodeEl(
						nodx.Class(
							"block break-all rounded-md border border-base-400 bg-base-100",
							"px-3 py-2 text-xs text-content select-all",
						),
						nodx.Text(enrollURL),
					),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm text-content"),
						nodx.Text("Or share the token alone, for text-only channels:"),
					),
					nodx.CodeEl(
						nodx.Class(
							"block break-all rounded-md border border-base-400 bg-base-100",
							"px-3 py-2 text-xs text-content select-all",
						),
						nodx.Text(token),
					),
				),
				nodx.P(
					nodx.Class("text-sm text-warning"),
					nodx.Role("alert"),
					nodx.Text("Copy this token now. It will not be shown again."),
				),
				nodx.A(
					nodx.Href(adminHomePath),
					nodx.Class(
						"block w-full rounded-md border border-base-400 bg-base-100 text-content",
						"text-center font-medium py-2 px-3 hover:opacity-90 focus:outline-none",
						"focus:ring-2 focus:ring-content",
					),
					nodx.Text("Back to administration"),
				),
			),
		),
	)
}

// ForbiddenPage renders the generic page shown when a state-changing
// administration request fails its anti-forgery check.
func ForbiddenPage() nodx.Node {
	return Page(config.UI{}, adminTitle,
		nodx.Main(
			nodx.Class("min-h-screen flex items-center justify-center px-4"),
			nodx.Div(
				nodx.Class(
					"w-full max-w-sm bg-base-200 border border-base-400 rounded-lg p-8 space-y-2",
				),
				nodx.H1(
					nodx.Class("text-lg font-semibold text-content"),
					nodx.Text("Forbidden"),
				),
				nodx.P(
					nodx.Class("text-sm text-content-muted"),
					nodx.Text("The request could not be completed."),
				),
			),
		),
	)
}
