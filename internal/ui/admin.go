package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
	"github.com/varavelio/zen-idp/internal/csrf"
)

// adminTitle is the document and page title of the administration
// interaction, also used as the product name when none is configured.
const adminTitle = "Administration"

// adminLoginAction is the form target of the administrator sign-in form.
const adminLoginAction = "/admin/login"

// adminLogoutAction is the form target of the administrator sign-out form.
const adminLogoutAction = "/admin/logout"

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
// authenticated administrator, including the protected sign-out form. token
// is the anti-forgery token that protects the sign-out submission.
func AdminHomePage(settings config.UI, token string) nodx.Node {
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
