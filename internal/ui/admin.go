package ui

import (
	"strings"

	nodx "github.com/varavelio/nodxgo"
	lucide "github.com/varavelio/nodxgo-lucide"
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

// adminLocksAction is the form target of the lock-management form.
const adminLocksAction = "/admin/locks"

// adminHomePath is the administration landing page, the destination of the
// link shown after an enrollment token is created and of the product
// identity in the administration header.
const adminHomePath = "/admin"

// Lock-management action values submitted to the administration handler.
const (
	lockActionLock       = "lock"
	lockActionUnlock     = "unlock"
	lockActionClearPanic = "clear_panic"
)

// enrollmentDurationOptions are the fixed enrollment-link duration choices
// with their human-readable labels and Go duration values; no expiration is
// expressed as a duration far beyond any practical horizon.
var enrollmentDurationOptions = []struct {
	label string
	value string
}{
	{"5 minutes", "5m"},
	{"10 minutes", "10m"},
	{"15 minutes", "15m"},
	{"30 minutes", "30m"},
	{"1 hour", "1h"},
	{"2 hours", "2h"},
	{"3 hours", "3h"},
	{"6 hours", "6h"},
	{"12 hours", "12h"},
	{"1 day", "24h"},
	{"3 days", "72h"},
	{"1 week", "168h"},
	{"30 days", "720h"},
	{"No expiration", "999999h"},
}

// defaultEnrollmentDuration is the preselected enrollment-link duration.
const defaultEnrollmentDuration = "1h"

// LockStatus describes the disposable lock state of one configured user on
// the administration home.
type LockStatus struct {
	// Subject is the user's stable subject.
	Subject string
	// Login is the user's optional additional login identifier, empty when
	// the user has none.
	Login string
	// AdminLocked reports whether an administrative lock gates the user.
	AdminLocked bool
	// Panicked reports whether a panic lock gates the user.
	Panicked bool
}

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
	return page(settings, adminTitle,
		standalonePage(settings, name, "Administrator sign-in", "max-w-md",
			nodx.If(failure != "", errorAlert(failure)),
			nodx.FormEl(
				nodx.Action(adminLoginAction),
				nodx.Method("post"),
				nodx.Class("space-y-5"),
				csrfField(token),
				textInput(
					"password",
					"password",
					"Administrator password",
					"current-password",
					"password",
					lucide.KeyRound(nodx.Class("size-4")),
					nodx.Placeholder("Enter your password"),
					nodx.Required(true),
					nodx.Autofocus(true),
				),
				actionButton(buttonPrimary, "Sign in", lucide.LogIn(nodx.Class("size-4"))),
			),
		),
	)
}

// adminHeader renders the shared administration header: the product
// identity on the left and the theme switcher and sign-out form on the
// right. csrfToken protects the sign-out form.
func adminHeader(cfg config.UI, name, csrfToken string) nodx.Node {
	return nodx.Header(
		nodx.Class("sticky top-0 z-40 border-b border-base-400 bg-base-100"),
		nodx.Div(
			nodx.Class(
				"mx-auto flex h-14 w-full max-w-5xl items-center justify-between gap-3 px-4",
			),
			nodx.A(
				nodx.Href(adminHomePath),
				nodx.Class("flex min-w-0 items-end gap-2.5"),
				brandMark(cfg, "h-7 w-auto shrink-0"),
				nodx.If(
					strings.TrimSpace(name) != "",
					nodx.SpanEl(
						nodx.Class("truncate font-semibold text-content text-xl"),
						nodx.Text(name),
					),
				),
			),
			nodx.Div(
				nodx.Class("flex shrink-0 items-center gap-2"),
				themeToggle(),
				signOutForm(csrfToken),
			),
		),
	)
}

// signOutForm renders the protected administrator sign-out form as a
// compact icon button.
func signOutForm(csrfToken string) nodx.Node {
	return nodx.FormEl(
		nodx.Action(adminLogoutAction),
		nodx.Method("post"),
		nodx.Class("inline"),
		csrfField(csrfToken),
		nodx.Button(
			nodx.Attr("type", "submit"),
			nodx.Class(
				"inline-flex size-9 items-center justify-center rounded-md",
				"border border-base-400 bg-base-100 text-content-muted",
				"transition-colors hover:text-content focus:outline-none focus:ring-2 focus:ring-content",
			),
			nodx.TitleAttr("Sign out"),
			nodx.Aria("label", "Sign out"),
			lucide.LogOut(nodx.Class("size-4")),
		),
	)
}

// AdminHomePage renders the administration landing page shown to an
// authenticated administrator: one card per configured user with the
// enrollment-link dialog and the lock-management actions, plus the link to
// the audit log. token is the anti-forgery token that protects the form
// submissions; failure is an optional message shown when the last
// administration action was rejected; locks carries the disposable lock
// state of every configured user.
func AdminHomePage(
	settings config.UI,
	token, failure string,
	locks []LockStatus,
) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return page(settings, adminTitle,
		adminHeader(settings, name, token),
		nodx.Main(
			nodx.Class("flex-1"),
			nodx.Div(
				nodx.Class("mx-auto w-full max-w-5xl space-y-6 px-4 py-8"),
				nodx.Div(
					nodx.Class("flex flex-wrap items-center justify-between gap-3"),
					nodx.Div(
						nodx.Class("space-y-1"),
						nodx.H1(
							nodx.Class("text-xl font-semibold text-content"),
							nodx.Text("Users"),
						),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("Create enrollment links and manage access locks."),
						),
					),
					nodx.A(
						nodx.Href(adminAuditPath),
						nodx.Class(
							"inline-flex items-center gap-2 rounded-md border border-base-400",
							"bg-base-100 px-3 py-2 text-sm font-medium text-content",
							"transition-opacity hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
						),
						lucide.ScrollText(nodx.Class("size-4")),
						nodx.Text("Audit log"),
					),
				),
				nodx.If(failure != "", errorAlert(failure)),
				nodx.If(
					len(locks) == 0,
					nodx.Div(
						nodx.Class(
							"flex flex-col items-center gap-2 rounded-lg border border-dashed",
							"border-base-400 py-16 text-center",
						),
						lucide.Users(nodx.Class("size-8 text-content-muted")),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("No users are configured."),
						),
					),
				),
				nodx.If(
					len(locks) > 0,
					nodx.Div(
						nodx.Class("grid gap-4 desk:grid-cols-2"),
						nodx.Map(locks, func(lock LockStatus) nodx.Node {
							return userCard(lock, token)
						}),
					),
				),
			),
		),
	)
}

// userCard renders one configured user: the identity and lock status, the
// enrollment-link dialog trigger, and the lock-management actions.
func userCard(lock LockStatus, token string) nodx.Node {
	return nodx.Div(
		nodx.Class("flex flex-col gap-3 rounded-lg border border-base-400 bg-base-200 p-4"),
		nodx.Div(
			nodx.Class("flex items-start justify-between gap-2"),
			nodx.Div(
				nodx.Class("min-w-0 space-y-0.5"),
				nodx.P(
					nodx.Class("truncate font-mono text-lg font-medium text-content"),
					nodx.Text(lock.Subject),
				),
				nodx.If(
					lock.Login != "",
					nodx.P(
						nodx.Class("truncate text-base text-content-muted"),
						nodx.Text(lock.Login),
					),
				),
			),
			statusBadge(lock),
		),
		enrollmentDialog(lock.Subject, token),
		lockActions(lock, token),
	)
}

// statusBadge renders the pill that reports the user's disposable lock
// state.
func statusBadge(lock LockStatus) nodx.Node {
	var icon nodx.Node
	var class string
	switch {
	case lock.Panicked:
		icon = lucide.TriangleAlert(nodx.Class("size-3"))
		class = "bg-error/15 text-error"
	case lock.AdminLocked:
		icon = lucide.Lock(nodx.Class("size-3"))
		class = "bg-warning/15 text-warning"
	default:
		icon = lucide.BadgeCheck(nodx.Class("size-3"))
		class = "bg-base-300 text-success"
	}
	return nodx.SpanEl(
		nodx.Class(
			"inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium "+class,
		),
		icon,
		nodx.Text(lockStatusText(lock)),
	)
}

// enrollmentDialog renders the enrollment-link trigger and its native
// modal dialog, which asks only for the token duration: the subject is
// fixed to the user the dialog belongs to. The shared script opens and
// closes the dialog.
func enrollmentDialog(subject, token string) nodx.Node {
	return nodx.Div(
		nodx.Button(
			nodx.Attr("type", "button"),
			nodx.Attr("data-dialog-open", "enroll-"+subject),
			nodx.Class(
				"inline-flex w-full items-center justify-center gap-2 rounded-md",
				"bg-content px-3 py-2 text-sm font-medium text-base-100",
				"transition-opacity hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-content",
			),
			lucide.Link(nodx.Class("size-4")),
			nodx.Text("Enrollment link"),
		),
		nodx.Dialog(
			nodx.Id("enroll-"+subject),
			nodx.Class(
				"fixed inset-0 m-auto w-[calc(100%-2rem)] max-w-md rounded-lg border border-base-400",
				"bg-base-200 p-6 text-content backdrop:bg-black/60",
			),
			nodx.FormEl(
				nodx.Action(adminTokensAction),
				nodx.Method("post"),
				nodx.Class("space-y-5"),
				csrfField(token),
				nodx.Input(
					nodx.Attr("type", "hidden"),
					nodx.Name("subject"),
					nodx.Value(subject),
				),
				nodx.Div(
					nodx.Class("space-y-1"),
					nodx.P(
						nodx.Class("text-sm font-medium text-content"),
						nodx.Text("Enrollment link for "+subject),
					),
					nodx.P(
						nodx.Class("text-xs text-content-muted"),
						nodx.Text("The user reveals their TOTP secret exactly once."),
					),
				),
				nodx.Div(
					nodx.Class("space-y-2"),
					nodx.LabelEl(
						nodx.Attr("for", "duration-"+subject),
						nodx.Class("block text-sm font-medium text-content"),
						nodx.Text("Duration"),
					),
					nodx.SelectEl(
						nodx.Name("duration"),
						nodx.Id("duration-"+subject),
						nodx.Class(
							"w-full rounded-md border border-base-400 bg-base-100 px-3 py-2.5 text-sm",
							"text-content focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Map(enrollmentDurationOptions, func(option struct {
							label string
							value string
						},
						) nodx.Node {
							return nodx.Option(
								nodx.Value(option.value),
								nodx.Selected(option.value == defaultEnrollmentDuration),
								nodx.Text(option.label),
							)
						}),
					),
				),
				nodx.Div(
					nodx.Class("flex justify-end gap-2"),
					nodx.Button(
						nodx.Attr("type", "button"),
						nodx.Attr("data-dialog-close"),
						nodx.Class(
							"rounded-md border border-base-400 bg-base-100 px-3 py-2 text-sm",
							"font-medium text-content transition-opacity hover:opacity-90",
							"focus:outline-none focus:ring-2 focus:ring-content",
						),
						nodx.Text("Cancel"),
					),
					nodx.Button(
						nodx.Attr("type", "submit"),
						nodx.Class(
							"inline-flex items-center gap-2 rounded-md bg-content px-3 py-2 text-sm",
							"font-medium text-base-100 transition-opacity hover:opacity-90",
							"focus:outline-none focus:ring-2 focus:ring-content",
						),
						lucide.Send(nodx.Class("size-4")),
						nodx.Text("Create link"),
					),
				),
			),
		),
	)
}

// lockActions renders the lock-management form of one user: the lock,
// unlock, or clear-panic action depending on the current state.
func lockActions(lock LockStatus, token string) nodx.Node {
	return nodx.FormEl(
		nodx.Action(adminLocksAction),
		nodx.Method("post"),
		nodx.Class("flex flex-col gap-2"),
		csrfField(token),
		nodx.Input(
			nodx.Attr("type", "hidden"),
			nodx.Name("subject"),
			nodx.Value(lock.Subject),
		),
		nodx.If(
			!lock.AdminLocked,
			lockActionButton(
				lockActionLock,
				"Lock",
				buttonSecondary,
				lucide.Lock(nodx.Class("size-4")),
			),
		),
		nodx.If(
			lock.AdminLocked,
			lockActionButton(
				lockActionUnlock,
				"Unlock",
				buttonSecondary,
				lucide.LockOpen(nodx.Class("size-4")),
			),
		),
		nodx.If(
			lock.Panicked,
			lockActionButton(
				lockActionClearPanic,
				"Clear panic",
				buttonDanger,
				lucide.TriangleAlert(nodx.Class("size-4")),
			),
		),
	)
}

// lockActionButton renders a lock-management submit button carrying the
// given action value, label, tone, and leading icon.
func lockActionButton(action, label string, tone buttonTone, icon nodx.Node) nodx.Node {
	class := "inline-flex w-full items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-opacity hover:opacity-90 focus:outline-none focus:ring-2"
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
		nodx.Name("action"),
		nodx.Value(action),
		nodx.Class(class),
		icon,
		nodx.Text(label),
	)
}

// EnrollmentTokenPage renders the one-time display of a freshly created
// enrollment token bound to the given subject and absolute expiration,
// together with the shareable enrollment link that carries the token, the
// only supported way to deliver it. csrfToken protects the sign-out form of
// the shared header. The token is shown exactly once on this page, which
// must never be cached.
func EnrollmentTokenPage(
	settings config.UI,
	subject, expiresAt, enrollURL, csrfToken string,
) nodx.Node {
	name := settings.Name
	if name == "" {
		name = adminTitle
	}
	return page(settings, enrollmentTokenTitle,
		adminHeader(settings, name, csrfToken),
		nodx.Main(
			nodx.Class("flex-1"),
			nodx.Div(
				nodx.Class("mx-auto w-full max-w-lg space-y-6 px-4 py-8"),
				nodx.Div(
					nodx.Class("space-y-5"),
					lucide.ClockCheck(nodx.Class("size-16 mx-auto shrink-0 text-success")),
					nodx.Div(
						nodx.Class("space-y-0.5 text-center"),
						nodx.H1(
							nodx.Class("text-lg font-semibold text-content"),
							nodx.Text("Enrollment token created."),
						),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("Subject: "+subject),
						),
						nodx.P(
							nodx.Class("text-sm text-content-muted"),
							nodx.Text("Expires: "+expiresAt),
						),
					),
					nodx.Div(
						nodx.Class("space-y-2"),
						nodx.Div(
							nodx.Class("flex items-center justify-between gap-2"),
							nodx.P(
								nodx.Class(
									"flex items-center gap-1.5 text-sm font-medium text-content",
								),
								lucide.Link(nodx.Class("size-4 text-content-muted")),
								nodx.Text("Enrollment link"),
							),
							copyButton(enrollURL),
						),
						nodx.CodeEl(
							nodx.Class(
								"block break-all rounded-md border border-base-400 bg-base-100",
								"px-3 py-2.5 text-xs text-content select-all",
							),
							nodx.Text(enrollURL),
						),
						nodx.P(
							nodx.Class("text-xs text-content-muted"),
							nodx.Text(
								"Send this link to the user through a trusted channel; it stops "+
									"working after it is used once.",
							),
						),
						nodx.A(
							nodx.Href(adminHomePath),
							nodx.Class(
								"mt-2 inline-flex w-full items-center justify-center gap-2 rounded-md",
								"border border-base-400 bg-base-100 px-3 py-2 text-sm font-medium",
								"text-content transition-opacity hover:opacity-90 focus:outline-none",
								"focus:ring-2 focus:ring-content",
							),
							lucide.ArrowLeft(nodx.Class("size-4")),
							nodx.Text("Back to administration"),
						),
					),
				),
			),
		),
	)
}

// lockStatusText returns the status label of the given user's disposable
// lock state.
func lockStatusText(lock LockStatus) string {
	switch {
	case lock.Panicked:
		return "Panic locked"
	case lock.AdminLocked:
		return "Admin locked"
	default:
		return "Active"
	}
}

// ForbiddenPage renders the generic page shown when a state-changing
// administration request fails its anti-forgery check.
func ForbiddenPage() nodx.Node {
	return noticePage(
		adminTitle,
		"Forbidden",
		"The request could not be completed.",
	)
}
