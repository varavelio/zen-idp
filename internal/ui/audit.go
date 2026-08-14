package ui

import (
	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
	"github.com/varavelio/zen-idp/internal/audit"
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
// stored details. csrfToken protects the sign-out form of the shared
// header.
func AuditLogPage(settings config.UI, records []AuditRecord, csrfToken string) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return Page(settings, auditTitle,
		adminHeader(settings, name, csrfToken),
		nodx.Main(
			nodx.Class("flex-1"),
			nodx.Div(
				nodx.Class("mx-auto w-full max-w-3xl space-y-6 px-4 py-8"),
				nodx.Div(
					nodx.Class("flex flex-wrap items-center justify-between gap-3"),
					nodx.Div(
						nodx.Class("space-y-1"),
						nodx.H1(
							nodx.Class("text-xl font-semibold text-content"),
							nodx.Text("Audit log"),
						),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("Security-relevant events, newest first."),
						),
					),
					nodx.A(
						nodx.Href(adminHomePath),
						nodx.Class(
							"inline-flex items-center gap-2 rounded-md border border-base-400",
							"bg-base-100 px-3 py-2 text-sm font-medium text-content",
							"transition-opacity hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						lucide.ArrowLeft(nodx.Class("size-4")),
						nodx.Text("Back"),
					),
				),
				nodx.If(
					len(records) == 0,
					nodx.Div(
						nodx.Class(
							"flex flex-col items-center gap-2 rounded-lg border border-dashed",
							"border-base-400 py-16 text-center",
						),
						lucide.ShieldAlert(nodx.Class("size-8 text-content-muted")),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("No audit records yet."),
						),
					),
				),
				nodx.If(
					len(records) > 0,
					nodx.Div(
						nodx.Class("space-y-3"),
						nodx.Map(records, auditRecordCard),
					),
				),
			),
		),
	)
}

// auditRecordCard renders one audit event with its category, instant,
// affected subject, and stored details.
func auditRecordCard(record AuditRecord) nodx.Node {
	return nodx.Div(
		nodx.Class("space-y-2 rounded-lg border border-base-400 bg-base-200 p-4"),
		nodx.Div(
			nodx.Class("flex items-center justify-between gap-2"),
			nodx.Div(
				nodx.Class("flex min-w-0 items-center gap-2"),
				auditCategoryIcon(record.Category),
				nodx.P(
					nodx.Class("truncate font-mono text-sm font-medium text-content"),
					nodx.Text(record.Category),
				),
			),
			nodx.Time(
				nodx.Attr("datetime", record.At),
				nodx.Class("shrink-0 text-xs text-content-muted"),
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
}

// auditCategoryIcon returns the semantic icon of one audit category, with
// the error tone for panic actions and the warning tone for rate-limit
// events.
func auditCategoryIcon(category string) nodx.Node {
	muted := nodx.Class("size-4 text-content-muted")
	switch audit.Category(category) {
	case audit.CategoryAdminAuthentication:
		return lucide.ShieldCheck(muted)
	case audit.CategoryEnrollmentTokenCreated:
		return lucide.Link(muted)
	case audit.CategoryEnrollmentTokenConsumed:
		return lucide.ScanLine(muted)
	case audit.CategoryLockChanged:
		return lucide.Lock(muted)
	case audit.CategoryPanicAction:
		return lucide.TriangleAlert(nodx.Class("size-4 text-error"))
	case audit.CategorySessionRevoked:
		return lucide.LogOut(muted)
	case audit.CategoryRateLimit:
		return lucide.Timer(nodx.Class("size-4 text-warning"))
	default:
		return lucide.ShieldAlert(muted)
	}
}
