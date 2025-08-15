package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Credential Definition Types and Operations
/// @dev Core types for managing credential definitions in the anoncreds system

/// @notice Public credential definition data structure
/// @dev Wraps the underlying FFI object handle for credential definitions
type CredentialDefinition struct {
	*ObjectHandle
}

/// @notice Private credential definition data structure
/// @dev Contains sensitive key material that must be kept secure
type CredentialDefinitionPrivate struct {
	*ObjectHandle
}

/// @notice Configuration options for creating a new credential definition
/// @dev All fields are required except Schema which is handled internally
type CreateCredentialDefinitionOptions struct {
	SchemaID          string  `json:"schema_id"`
	Schema            *Schema `json:"-"`
	IssuerID          string  `json:"issuer_id"`
	Tag               string  `json:"tag"`
	SignatureType     string  `json:"signature_type"`
	SupportRevocation bool    `json:"support_revocation"`
}

/// @notice Result structure returned after creating a credential definition
/// @dev Contains both public and private components of the credential definition
type CreateCredentialDefinitionResult struct {
	CredentialDefinition        *CredentialDefinition        /// @notice Public credential definition
	CredentialDefinitionPrivate *CredentialDefinitionPrivate /// @notice Private key material
	KeyCorrectnessProof         *KeyCorrectnessProof        /// @notice Proof of key correctness
}

/// @notice Creates a new credential definition from the provided options
/// @param options Configuration options for the credential definition
/// @return Result containing both public and private components, and any error encountered
/// @dev This operation generates cryptographic keys and should be handled securely
func CreateCredentialDefinition(options CreateCredentialDefinitionOptions) (*CreateCredentialDefinitionResult, error) {
	credDef, credDefPrivate, keyProof, err := ffi.CreateCredentialDefinition(
		options.SchemaID,
		options.Schema.handle,
		options.IssuerID,
		options.Tag,
		options.SignatureType,
		options.SupportRevocation,
	)
	if err != nil {
		return nil, err
	}
	
	return &CreateCredentialDefinitionResult{
		CredentialDefinition:        &CredentialDefinition{ObjectHandle: &ObjectHandle{handle: credDef}},
		CredentialDefinitionPrivate: &CredentialDefinitionPrivate{ObjectHandle: &ObjectHandle{handle: credDefPrivate}},
		KeyCorrectnessProof:         &KeyCorrectnessProof{ObjectHandle: &ObjectHandle{handle: keyProof}},
	}, nil
}

/// @notice Creates a credential definition from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A credential definition object and any error encountered
/// @dev Supports multiple input formats for flexibility
func CredentialDefinitionFromJSON(jsonData interface{}) (*CredentialDefinition, error) {
	var jsonStr string
	
	switch data := jsonData.(type) {
	case string:
		jsonStr = data
	case map[string]interface{}:
		bytes, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		jsonStr = string(bytes)
	case []byte:
		jsonStr = string(data)
	default:
		return nil, fmt.Errorf("invalid JSON data type")
	}
	
	handle, err := ffi.ObjectFromJSON("CredentialDefinition", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &CredentialDefinition{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}