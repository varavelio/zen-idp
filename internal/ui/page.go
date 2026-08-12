package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// Page renders the document shell shared by every Zen IdP page: the document
// declaration, the head with the product title and optional favicon, the
// compiled stylesheet link, and the given body content.
func Page(cfg config.UI, title string, body ...nodx.Node) nodx.Node {
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
				nodx.Link(nodx.Rel("stylesheet"), nodx.Href("/build/app.css")),
			),
			nodx.Body(body...),
		),
	)
}
