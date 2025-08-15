package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Credential Offer Types and Operations
/// @dev Core functionality for managing credential offers

/// @notice Represents an offer for a credential from an issuer
/// @dev Wraps the underlying FFI object handle for credential offers
type CredentialOffer struct {
	*ObjectHandle
}

/// @notice Configuration options for creating a credential offer
/// @dev All fields are required and must match the credential definition
type CreateCredentialOfferOptions struct {
	SchemaID               string                 `json:"schema_id"`
	CredentialDefinitionID string                 `json:"cred_def_id"`
	KeyCorrectnessProof    interface{}            `json:"key_correctness_proof"`
}

/// @notice Creates a new credential offer using the provided options
/// @param options Configuration options for the credential offer
/// @return A new credential offer object and any error encountered
/// @dev Matches the Node.js API exactly for compatibility
func CreateCredentialOffer(options CreateCredentialOfferOptions) (*CredentialOffer, error) {
	var kcpHandle *ffi.ObjectHandle
	
	// Handle KeyCorrectnessProof - can be either an ObjectHandle or JSON
	switch kcp := options.KeyCorrectnessProof.(type) {
	case *KeyCorrectnessProof:
		// Already an object handle
		kcpHandle = kcp.handle
	case map[string]interface{}:
		// JSON object - convert to handle
		jsonBytes, err := json.Marshal(kcp)
		if err != nil {
			return nil, err
		}
		handle, err := ffi.ObjectFromJSON("KeyCorrectnessProof", string(jsonBytes))
		if err != nil {
			return nil, err
		}
		defer handle.Clear() // Clean up temporary handle
		kcpHandle = handle
	case string:
		// JSON string
		handle, err := ffi.ObjectFromJSON("KeyCorrectnessProof", kcp)
		if err != nil {
			return nil, err
		}
		defer handle.Clear() // Clean up temporary handle
		kcpHandle = handle
	default:
		return nil, fmt.Errorf("invalid KeyCorrectnessProof type")
	}
	
	// Create the credential offer using the C API
	offerHandle, err := ffi.CreateCredentialOffer(
		options.SchemaID,
		options.CredentialDefinitionID,
		kcpHandle,
	)
	if err != nil {
		return nil, err
	}
	
	return &CredentialOffer{
		ObjectHandle: &ObjectHandle{handle: offerHandle},
	}, nil
}

/// @notice Creates a credential offer from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A credential offer object and any error encountered
/// @dev Supports multiple input formats for flexibility
func CredentialOfferFromJSON(jsonData interface{}) (*CredentialOffer, error) {
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
	
	handle, err := ffi.ObjectFromJSON("CredentialOffer", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &CredentialOffer{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}