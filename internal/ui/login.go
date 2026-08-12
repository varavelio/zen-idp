package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// loginTitle is the document and page title of the login interaction, also
// used as the product name when none is configured.
const loginTitle = "Sign in"

// LoginPage renders the sign-in interaction: the product identity, the
// identifier and one-time-code fields, and an optional failure message.
// action is the form target that carries the pending authorization request
// parameters, which are forwarded unchanged when the form is submitted.
func LoginPage(settings config.UI, action, failure string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = loginTitle
	}
	return Page(settings, loginTitle,
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
						nodx.Text("Sign in with your one-time code"),
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
					nodx.Action(action),
					nodx.Method("post"),
					nodx.Class("space-y-5"),
					nodx.Div(
						nodx.Class("space-y-2"),
						nodx.LabelEl(
							nodx.Attr("for", "identifier"),
							nodx.Class("block text-sm font-medium text-content"),
							nodx.Text("Login identifier"),
						),
						nodx.Input(
							nodx.Attr("type", "text"),
							nodx.Name("identifier"),
							nodx.Id("identifier"),
							nodx.Autocomplete("username"),
							nodx.Required(true),
							nodx.Autofocus(true),
							nodx.Class(
								"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm "+
									"text-content placeholder:text-content-muted focus:outline-none "+
									"focus:ring-2 focus:ring-content",
							),
						),
					),
					nodx.Div(
						nodx.Class("space-y-2"),
						nodx.LabelEl(
							nodx.Attr("for", "code"),
							nodx.Class("block text-sm font-medium text-content"),
							nodx.Text("One-time code"),
						),
						nodx.Input(
							nodx.Attr("type", "text"),
							nodx.Name("code"),
							nodx.Id("code"),
							nodx.Autocomplete("one-time-code"),
							nodx.Attr("inputmode", "numeric"),
							nodx.Attr("pattern", "[0-9]{6}"),
							nodx.Maxlength("6"),
							nodx.Required(true),
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
						nodx.Text(loginTitle),
					),
				),
			),
		),
	)
}

// InvalidRequestPage renders the generic page shown when a request cannot be
// processed because no trusted target exists for an error redirect.
func InvalidRequestPage() nodx.Node {
	return Page(config.UI{}, "Zen IdP",
		nodx.Main(
			nodx.Class("min-h-screen flex items-center justify-center px-4"),
			nodx.Div(
				nodx.Class(
					"w-full max-w-sm bg-base-200 border border-base-400 rounded-lg p-8 space-y-2",
				),
				nodx.H1(
					nodx.Class("text-lg font-semibold text-content"),
					nodx.Text("Invalid authorization request"),
				),
				nodx.P(
					nodx.Class("text-sm text-content-muted"),
					nodx.Text("The authorization request could not be processed."),
				),
			),
		),
	)
}
