package dto

// Wire-stable error codes. These strings appear in JSON responses and are
// part of the public contract — treat them as versioned. Never log or emit
// these codes from anywhere except apiresp.
const (
	CodeValidation   = "validation"
	CodeInvalidInput = "invalid_input"
	CodeConflict     = "conflict"
	CodeNotFound     = "not_found"
	CodeUnauthorized = "unauthorized"
	CodeForbidden    = "forbidden"
	CodeTimeout      = "timeout"
	CodeUnavailable  = "unavailable"
	CodeInternal     = "internal"
)

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ErrorEnvelope struct {
	Error ErrorBody `json:"error"`
}
