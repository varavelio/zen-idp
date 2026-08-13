package ui

import (
	nodx "github.com/varavelio/nodxgo"
	"github.com/varavelio/zen-idp/internal/config"
)

// auditTitle is the document and page title of the audit log page.
const auditTitle = "Audit log"

// adminAuditPath is the audit log page of the administration interaction,
// the destination of the link shown on the administration home.
const adminAuditPath = "/admin/audit"

// AuditRecord is one security-relevant event as shown on the audit log
// page, with its instant already formatted and its details as stored JSON.
type AuditRecord struct {
	// At is the canonical UTC instant of the event.
	At string
	// Category is the event category.
	Category string
	// Subject is the affected subject, empty when the event carries none.
	Subject string
	// Details is the stored JSON details object.
	Details string
}

// AuditLogPage renders the audit log page shown to an authenticated
// administrator: the most recent security-relevant events, newest first,
// each with its instant, category, affected subject when applicable, and
// stored details, plus a link back to the administration home.
func AuditLogPage(settings config.UI, records []AuditRecord) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return Page(settings, auditTitle,
		nodx.Main(
			nodx.Class("min-h-screen flex items-center justify-center px-4"),
			nodx.Div(
				nodx.Class(
					"w-full max-w-2xl bg-base-200 border border-base-400 rounded-lg p-8 space-y-6",
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
						nodx.Text("Audit log"),
					),
				),
				nodx.If(
					len(records) == 0,
					nodx.P(
						nodx.Class("text-sm text-content-muted"),
						nodx.Text("No audit records yet."),
					),
				),
				nodx.Map(records, func(record AuditRecord) nodx.Node {
					return nodx.Div(
						nodx.Class(
							"space-y-1 rounded-md border border-base-400 bg-base-100 p-3",
						),
						nodx.Div(
							nodx.Class("flex items-center justify-between gap-2"),
							nodx.P(
								nodx.Class("text-sm font-medium text-content"),
								nodx.Text(record.Category),
							),
							nodx.Time(
								nodx.Attr("datetime", record.At),
								nodx.Class("text-xs text-content-muted"),
								nodx.Text(record.At),
							),
						),
						nodx.If(
							record.Subject != "",
							nodx.P(
								nodx.Class("text-xs text-content-muted"),
								nodx.Text("Subject: "+record.Subject),
							),
						),
						nodx.CodeEl(
							nodx.Class("block break-all text-xs text-content-muted"),
							nodx.Text(record.Details),
						),
					)
				}),
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
