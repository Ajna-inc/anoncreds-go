package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Credential Request Types and Operations
/// @dev Core functionality for managing credential requests

/// @notice Represents a request for a credential from a prover
/// @dev Wraps the underlying FFI object handle for credential requests
type CredentialRequest struct {
	*ObjectHandle
}

/// @notice Metadata associated with a credential request
/// @dev Contains additional data needed for processing the credential
type CredentialRequestMetadata struct {
	*ObjectHandle
}

/// @notice Configuration options for creating a credential request
/// @dev All fields except ProverDID are required
type CreateCredentialRequestOptions struct {
	Entropy                string                 `json:"entropy"`
	ProverDID              *string                `json:"prover_did,omitempty"`
	CredentialDefinition   *CredentialDefinition  `json:"-"`
	LinkSecret             *LinkSecret            `json:"-"`
	LinkSecretID           string                 `json:"link_secret_id"`
	CredentialOffer        *CredentialOffer       `json:"-"`
}

/// @notice Result structure returned after creating a credential request
/// @dev Contains both the request and its associated metadata
type CreateCredentialRequestResult struct {
	CredentialRequest         *CredentialRequest         /// @notice The credential request
	CredentialRequestMetadata *CredentialRequestMetadata /// @notice Associated metadata
}

/// @notice Creates a new credential request using the provided options
/// @param options Configuration options for the credential request
/// @return Result containing both request and metadata, and any error encountered
/// @dev Validates all required fields before creating the request
func CreateCredentialRequest(options CreateCredentialRequestOptions) (*CreateCredentialRequestResult, error) {
	if options.CredentialDefinition == nil {
		return nil, fmt.Errorf("credential definition is required")
	}
	if options.LinkSecret == nil {
		return nil, fmt.Errorf("link secret is required")
	}
	if options.CredentialOffer == nil {
		return nil, fmt.Errorf("credential offer is required")
	}
	
	credReq, credReqMeta, err := ffi.CreateCredentialRequest(
		options.Entropy,
		options.ProverDID,
		options.CredentialDefinition.handle,
		options.LinkSecret.Value,
		options.LinkSecretID,
		options.CredentialOffer.handle,
	)
	if err != nil {
		return nil, err
	}
	
	return &CreateCredentialRequestResult{
		CredentialRequest:         &CredentialRequest{ObjectHandle: &ObjectHandle{handle: credReq}},
		CredentialRequestMetadata: &CredentialRequestMetadata{ObjectHandle: &ObjectHandle{handle: credReqMeta}},
	}, nil
}

/// @notice Creates a credential request from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A credential request object and any error encountered
/// @dev Supports multiple input formats for flexibility
func CredentialRequestFromJSON(jsonData interface{}) (*CredentialRequest, error) {
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
	
	handle, err := ffi.ObjectFromJSON("CredentialRequest", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &CredentialRequest{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

/// @notice Creates credential request metadata from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A credential request metadata object and any error encountered
/// @dev Supports multiple input formats for flexibility
func CredentialRequestMetadataFromJSON(jsonData interface{}) (*CredentialRequestMetadata, error) {
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
	
	handle, err := ffi.ObjectFromJSON("CredentialRequestMetadata", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &CredentialRequestMetadata{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}