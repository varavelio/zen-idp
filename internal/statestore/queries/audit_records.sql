-- name: CreateAuditRecord :exec
INSERT INTO audit_records (
    id,
    created_at,
    category,
    sub,
    details
) VALUES (
    sqlc.arg(id),
    sqlc.arg(created_at),
    sqlc.arg(category),
    sqlc.arg(sub),
    sqlc.arg(details)
);

-- name: ListAuditRecords :many
SELECT id, created_at, category, sub, details
FROM audit_records
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(limit);

-- name: DeleteAuditRecordsBefore :execrows
DELETE FROM audit_records
WHERE created_at <= sqlc.arg(before);
