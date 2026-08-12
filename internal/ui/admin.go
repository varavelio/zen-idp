package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// adminTitle is the document and page title of the administration
// interaction, also used as the product name when none is configured.
const adminTitle = "Administration"

// adminLoginAction is the form target of the administrator sign-in form.
const adminLoginAction = "/admin/login"

// AdminLoginPage renders the administrator sign-in interaction: the product
// identity, a password field, and an optional failure message.
func AdminLoginPage(settings config.UI, failure string) nodx.Node {
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
								"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm "+
									"text-content placeholder:text-content-muted focus:outline-none "+
									"focus:ring-2 focus:ring-content",
							),
						),
					),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"w-full rounded-md bg-content text-base-100 font-medium py-2 px-3 "+
								"hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Text("Sign in"),
					),
				),
			),
		),
	)
}

// AdminHomePage renders the minimal administration landing page shown to an
// authenticated administrator.
func AdminHomePage(settings config.UI) nodx.Node {
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
			),
		),
	)
}
