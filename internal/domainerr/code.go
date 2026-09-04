package domainerr

// Code is a stable, transport-independent domain error code.
type Code string

const (
	CodeValidationFailed    Code = "validation_failed"
	CodeUnauthenticated     Code = "unauthenticated"
	CodeForbidden           Code = "forbidden"
	CodeNotFound            Code = "not_found"
	CodeMethodNotAllowed    Code = "method_not_allowed"
	CodeRevisionConflict    Code = "revision_conflict"
	CodeIdempotencyConflict Code = "idempotency_conflict"
	CodeRateLimited         Code = "rate_limited"
	CodeTimeout             Code = "timeout"
	CodeInternalError       Code = "internal_error"

	CodeUnknownField      Code = "unknown_field"
	CodeReservedKey       Code = "reserved_key"
	CodeImmutableField    Code = "immutable_field"
	CodeRevisionMismatch  Code = "revision_mismatch"
	CodeNotWritable       Code = "not_writable"
	CodeWrongType         Code = "wrong_type"
	CodeWaitTimeout       Code = "wait_timeout"
	CodeStoreWiped        Code = "store_wiped"
	CodeUnauthorized      Code = "unauthorized"
	CodeOriginNotAllowed  Code = "origin_not_allowed"
	CodeTLSUnsupported    Code = "tls_unsupported"
	CodeNoSuchInstance    Code = "no_such_instance"
	CodeEndOfMibView      Code = "end_of_mib_view"
	CodeUSMAlgUnsupported Code = "usm_alg_unsupported"
)

var catalog = []struct {
	Code      Code
	Retryable bool
}{
	{CodeValidationFailed, false},
	{CodeUnauthenticated, false},
	{CodeForbidden, false},
	{CodeNotFound, false},
	{CodeMethodNotAllowed, false},
	{CodeRevisionConflict, true},
	{CodeIdempotencyConflict, false},
	{CodeRateLimited, true},
	{CodeTimeout, true},
	{CodeInternalError, true},
	{CodeUnknownField, false},
	{CodeReservedKey, false},
	{CodeImmutableField, false},
	{CodeRevisionMismatch, true},
	{CodeNotWritable, false},
	{CodeWrongType, false},
	{CodeWaitTimeout, true},
	{CodeStoreWiped, false},
	{CodeUnauthorized, false},
	{CodeOriginNotAllowed, false},
	{CodeTLSUnsupported, false},
	{CodeNoSuchInstance, false},
	{CodeEndOfMibView, false},
	{CodeUSMAlgUnsupported, false},
}

// Codes returns the stable catalog in documented order.
func Codes() []Code {
	out := make([]Code, len(catalog))
	for i, e := range catalog {
		out[i] = e.Code
	}
	return out
}

// Retryable reports the catalog default for code. Unknown codes are not retryable.
func Retryable(code Code) bool {
	for _, e := range catalog {
		if e.Code == code {
			return e.Retryable
		}
	}
	return false
}
