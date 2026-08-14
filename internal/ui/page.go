package ui

import (
	"strings"

	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/config"
)

// projectName is the product name shown in the shared footer.
const projectName = "Zen IdP"

// projectRepoURL is the public project repository linked from the shared
// footer.
const projectRepoURL = "https://github.com/varavelio/zen-idp"

// Bundled project logo paths served from the embedded static tree: the
// black mark for light mode, the white mark for dark mode, and the square
// icon used as the default favicon when none is configured.
const (
	zenLogoBlackPath = "/vendor/logo/logo-black.svg"
	zenLogoWhitePath = "/vendor/logo/logo-white.svg"
	zenIconPath      = "/vendor/logo/icon.svg"
)

// themeScriptPath is the client-side script that drives the theme picker,
// the native modal dialogs, and the copy buttons.
const themeScriptPath = "/vendor/app.js"

// page renders the document shell shared by every Zen IdP page: the
// document declaration, the head with the product title, the favicon
// (configured or bundled), the theme bootstrap script, and the compiled
// stylesheet, and the body with the given content and the shared footer.
func page(cfg config.UI, title string, body ...nodx.Node) nodx.Node {
	return nodx.Group(
		nodx.DocType(),
		nodx.Html(
			nodx.Attr("lang", "en"),
			nodx.Head(
				nodx.Meta(nodx.Charset("utf-8")),
				nodx.Meta(
					nodx.Name("viewport"),
					nodx.Attr("content", "width=device-width, initial-scale=1"),
				),
				nodx.TitleEl(nodx.Text(title)),
				nodx.If(
					cfg.FaviconURL != "",
					nodx.Link(nodx.Rel("icon"), nodx.Href(cfg.FaviconURL)),
				),
				nodx.If(
					cfg.FaviconURL == "",
					nodx.Link(nodx.Rel("icon"), nodx.Href(zenIconPath)),
				),
				nodx.Script(nodx.Src(themeScriptPath)),
				nodx.Link(nodx.Rel("stylesheet"), nodx.Href("/build/app.css")),
			),
			nodx.Body(
				nodx.Class("flex min-h-screen flex-col"),
				nodx.Group(body...),
				footer(),
			),
		),
	)
}

// footer renders the minimal centered footer shared by every page: the
// bundled project mark and a link to the project repository.
func footer() nodx.Node {
	return nodx.Footer(
		nodx.Class("py-6"),
		nodx.A(
			nodx.Href(projectRepoURL),
			nodx.Class(
				"mx-auto flex w-fit items-center gap-1.5 text-xs text-content-muted",
				"transition-colors hover:text-content",
			),
			brandMark(config.UI{}, "h-3.5 w-auto"),
			nodx.Text("Powered by "+projectName),
		),
	)
}

// brandMark renders the configured light and dark logos, one per color
// scheme; a missing logo falls back to the other configured one and then to
// the bundled Zen IdP mark. Sized by the given class.
func brandMark(cfg config.UI, class string) nodx.Node {
	lightURL := cfg.LogoLightURL
	if lightURL == "" {
		lightURL = cfg.LogoDarkURL
	}
	darkURL := cfg.LogoDarkURL
	if darkURL == "" {
		darkURL = cfg.LogoLightURL
	}
	if lightURL == "" {
		lightURL = zenLogoBlackPath
	}
	if darkURL == "" {
		darkURL = zenLogoWhitePath
	}
	return nodx.Group(
		nodx.Img(nodx.Class(class+" dark:hidden"), nodx.Src(lightURL), nodx.Alt("")),
		nodx.Img(nodx.Class("hidden "+class+" dark:block"), nodx.Src(darkURL), nodx.Alt("")),
	)
}

// themeToggle renders the theme preference dropdown: a trigger with the
// icon of the active theme and the label, and a menu with the system, light,
// and dark options. The shared script applies and persists the choice.
func themeToggle() nodx.Node {
	return nodx.Div(
		nodx.Class("relative"),
		nodx.Attr("data-theme-picker"),
		nodx.Button(
			nodx.Attr("type", "button"),
			nodx.Attr("data-theme-toggle"),
			nodx.Class(
				"relative inline-flex size-9 items-center justify-center rounded-md",
				"border border-base-400 bg-base-100 text-content-muted transition-colors",
				"hover:text-content focus:outline-none focus:ring-2 focus:ring-content",
				"desk:w-auto desk:gap-1.5 desk:px-2.5",
			),
			nodx.TitleAttr("Theme"),
			nodx.Aria("label", "Theme"),
			nodx.Aria("haspopup", "menu"),
			nodx.Aria("expanded", "false"),
			lucide.Palette(nodx.Attr("data-theme-icon-system"), nodx.Class("size-4")),
			lucide.Moon(nodx.Attr("data-theme-icon-dark"), nodx.Class("hidden size-4")),
			lucide.Sun(nodx.Attr("data-theme-icon-light"), nodx.Class("hidden size-4")),
			nodx.SpanEl(
				nodx.Class("hidden text-sm font-medium text-content desk:inline"),
				nodx.Text("Theme"),
			),
			lucide.ChevronDown(nodx.Class("hidden size-3.5 desk:inline")),
		),
		nodx.Div(
			nodx.Class(
				"absolute right-0 top-full z-50 mt-1 hidden min-w-44 rounded-lg",
				"border border-base-400 bg-base-100 p-1 shadow-sm",
			),
			nodx.Attr("data-theme-menu"),
			nodx.Role("menu"),
			themeOption("system", "System", lucide.Palette(nodx.Class("size-4"))),
			themeOption("light", "Light", lucide.Sun(nodx.Class("size-4"))),
			themeOption("dark", "Dark", lucide.Moon(nodx.Class("size-4"))),
		),
	)
}

// themeOption renders one selectable entry of the theme menu with the check
// mark of the active theme; the shared script toggles it.
func themeOption(theme, label string, icon nodx.Node) nodx.Node {
	return nodx.Button(
		nodx.Attr("type", "button"),
		nodx.Attr("data-theme-option", theme),
		nodx.Role("menuitemradio"),
		nodx.Aria("checked", "false"),
		nodx.Class(
			"flex w-full items-center gap-2 rounded-md px-3 py-2 text-left text-sm",
			"text-content transition-colors hover:bg-base-300 focus:bg-base-300",
			"focus:outline-none",
		),
		icon,
		nodx.Text(label),
		lucide.Check(
			nodx.Attr("data-theme-check"),
			nodx.Class("ml-auto hidden size-4 text-content-muted"),
		),
	)
}

// identityHeader renders the centered product identity of a standalone
// page: the logo and the product name on the same row, with an optional
// subtitle below. An overlong name truncates with an ellipsis instead of
// wrapping.
func identityHeader(cfg config.UI, name, subtitle string) nodx.Node {
	return nodx.Div(
		nodx.Class("flex w-full max-w-full flex-col items-center gap-2"),
		brandMark(cfg, "h-8 w-auto shrink-0"),
		nodx.If(
			strings.TrimSpace(name) != "",
			nodx.H1(
				nodx.Class("min-w-0 truncate text-xl font-semibold text-content"),
				nodx.Text(name),
			),
		),
		nodx.If(
			strings.TrimSpace(subtitle) != "",
			nodx.P(nodx.Class("text-sm text-content-muted"), nodx.Text(subtitle)),
		),
	)
}

// standalonePage renders the layout shared by every centered page that has
// no administration header: the decorative backdrop, the theme picker fixed
// at the top-right corner, and the given content in a card below the
// product identity.
func standalonePage(
	cfg config.UI,
	name, subtitle, widthClass string,
	content ...nodx.Node,
) nodx.Node {
	return nodx.Main(
		nodx.Class("flex flex-1 items-center justify-center px-4 py-10"),
		nodx.Div(nodx.Class("fixed right-4 top-4 z-50"), themeToggle()),
		nodx.Div(
			nodx.Class("relative w-full "+widthClass+" space-y-6 p-8"),
			identityHeader(cfg, name, subtitle),
			nodx.Group(content...),
		),
	)
}

// noticePage renders the small centered card shared by the stateless
// notice pages: a heading and a short message, without the product
// identity.
func noticePage(title, heading, message string) nodx.Node {
	return page(config.UI{}, title,
		nodx.Main(
			nodx.Class("flex flex-1 items-center justify-center px-4 py-10"),
			nodx.Div(nodx.Class("fixed right-4 top-4 z-50"), themeToggle()),
			nodx.Div(
				nodx.Class(
					"w-full max-w-sm space-y-1 rounded-lg border border-base-400 bg-base-200 p-6",
				),
				nodx.H1(nodx.Class("text-lg font-semibold text-content"), nodx.Text(heading)),
				nodx.P(nodx.Class("text-sm text-content-muted"), nodx.Text(message)),
			),
		),
	)
}

// errorAlert renders a failure message with the error tone and an alert
// icon.
func errorAlert(message string) nodx.Node {
	return nodx.Div(
		nodx.Class(
			"flex items-start gap-2 rounded-md border border-error/25 bg-error/10 p-3 text-sm text-error",
		),
		nodx.Role("alert"),
		lucide.CircleAlert(nodx.Class("mt-0.5 size-4 shrink-0")),
		nodx.P(nodx.Text(message)),
	)
}

// textInput renders a labeled text input with a leading icon, the shared
// field style of every form.
func textInput(
	id, name, label, autocomplete, inputType string,
	icon nodx.Node,
	extra ...nodx.Node,
) nodx.Node {
	return nodx.Div(
		nodx.Class("space-y-2"),
		nodx.LabelEl(
			nodx.Attr("for", id),
			nodx.Class("block text-sm font-medium text-content"),
			nodx.Text(label),
		),
		nodx.Div(
			nodx.Class("relative"),
			nodx.SpanEl(
				nodx.Class(
					"pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3",
					"text-content-muted",
				),
				icon,
			),
			nodx.Input(
				nodx.Attr("type", inputType),
				nodx.Name(name),
				nodx.Id(id),
				nodx.Autocomplete(autocomplete),
				nodx.Class(
					"w-full rounded-md border border-base-400 bg-base-100 py-2.5 pl-9 pr-3 text-sm",
					"text-content placeholder:text-content-muted focus:outline-none",
					"focus:ring-2 focus:ring-content",
				),
				nodx.Group(extra...),
			),
		),
	)
}

// buttonTone is the visual tone of an action button.
type buttonTone string

// Supported action button tones.
const (
	buttonPrimary   buttonTone = "primary"
	buttonSecondary buttonTone = "secondary"
	buttonDanger    buttonTone = "danger"
)

// actionButton renders a full-width submit button with a leading icon in
// the given tone.
func actionButton(tone buttonTone, label string, icon nodx.Node) nodx.Node {
	class := "inline-flex w-full items-center justify-center gap-2 rounded-md px-3 py-2.5 text-sm font-medium transition-opacity hover:opacity-90 focus:outline-none focus:ring-2"
	switch tone {
	case buttonPrimary:
		class += " bg-content text-base-100 focus:ring-content"
	case buttonDanger:
		class += " bg-error text-base-100 focus:ring-error"
	default:
		class += " border border-base-400 bg-base-100 text-content focus:ring-content"
	}
	return nodx.Button(
		nodx.Attr("type", "submit"),
		nodx.Class(class),
		icon,
		nodx.Text(label),
	)
}

// copyButton renders a button that copies text to the clipboard when
// clicked, flashing a confirmation; the shared script drives the
// interaction.
func copyButton(value string) nodx.Node {
	return nodx.Button(
		nodx.Attr("type", "button"),
		nodx.Attr("data-copy", value),
		nodx.Class(
			"inline-flex items-center gap-1.5 rounded-md border border-base-400 bg-base-100",
			"px-2.5 py-1.5 text-xs font-medium text-content-muted transition-colors",
			"hover:text-content focus:outline-none focus:ring-2 focus:ring-content",
		),
		lucide.Copy(nodx.Attr("data-copy-idle"), nodx.Class("size-3.5")),
		lucide.Check(nodx.Attr("data-copy-done"), nodx.Class("hidden size-3.5")),
		nodx.SpanEl(nodx.Attr("data-copy-label"), nodx.Text("Copy")),
	)
}

// labeledCodeBlock renders a titled, selectable code block with a copy
// button.
func labeledCodeBlock(title, value string) nodx.Node {
	return nodx.Div(
		nodx.Class("space-y-2"),
		nodx.Div(
			nodx.Class("flex items-center justify-between gap-2"),
			nodx.P(nodx.Class("text-sm font-medium text-content"), nodx.Text(title)),
			copyButton(value),
		),
		nodx.CodeEl(
			nodx.Class(
				"block break-all rounded-md border border-base-400 bg-base-100",
				"px-3 py-2 text-xs text-content select-all",
			),
			nodx.Text(value),
		),
	)
}
