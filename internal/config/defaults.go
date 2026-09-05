package config

const (
	DefaultAgentAddress       = ":161"
	DefaultTrapAddress        = ":162"
	DefaultDTLSAddress        = ":10161"
	DefaultDTLSTrapsAddress   = ":10162"
	DefaultMgmtAddress        = ":8088"
	DefaultRESTPath           = "/v1"
	DefaultMCPPath            = "/mcp"
	DefaultBodyLimit          = int64(1 << 20)
	DefaultMaxVarBinds        = 64
	DefaultMaxRepetitions     = 100
	DefaultMaxMessageBytes    = int64(64 << 10)
	DefaultMaxDatagramsPerSec = 10000
	DefaultMaxDatagramsPerIP  = 500
	DefaultMaxMessages        = 1000
	DefaultMaxTrapBytes       = int64(16 << 20)
	DefaultMaxWait            = "60s"
	DefaultEngineBoots        = 1
	MaxDocumentBytes          = 1 << 20
	MinTokenBytes             = 32
	MinUSMSecretBytes         = 8
	MinEngineIDOctets         = 5
	MaxEngineIDOctets         = 32
	MaxUSMUserNameBytes       = 32

	violationUnknownField       = "unknown_field"
	violationRequired           = "required"
	violationInvalidValue       = "invalid_value"
	violationReservedKey        = "reserved_key"
	violationDuplicateKey       = "duplicate_key"
	violationTooLarge           = "document_too_large"
	violationUnsupportedVersion = "unsupported_version"
	violationDuplicateID        = "duplicate_id"
	violationEmptyID            = "empty_id"
	violationTLSUnsupported     = "tls_unsupported"
	violationUSMAlgUnsupported  = "usm_alg_unsupported"
)
