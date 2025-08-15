package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Credential Types and Operations
/// @dev Core functionality for managing anonymous credentials

/// @notice Represents an anonymous credential
/// @dev Wraps the underlying FFI object handle for credentials
type Credential struct {
	*ObjectHandle
}

/// @notice Configuration options for creating a new credential
/// @dev All fields except RevocationConfig are required
type CreateCredentialOptions struct {
	CredentialDefinition        *CredentialDefinition
	CredentialDefinitionPrivate *CredentialDefinitionPrivate
	CredentialOffer            *CredentialOffer
	CredentialRequest          *CredentialRequest
	AttributeRawValues         map[string]string
	AttributeEncodedValues     map[string]string
	RevocationConfig           *ffi.RevocationConfig
}

/// @notice Creates a new credential using the provided options
/// @param options Configuration options for the credential
/// @return A new credential object and any error encountered
/// @dev Validates all required fields before creating the credential
func CreateCredential(options CreateCredentialOptions) (*Credential, error) {
	if options.CredentialDefinition == nil {
		return nil, fmt.Errorf("credential definition is required")
	}
	if options.CredentialDefinitionPrivate == nil {
		return nil, fmt.Errorf("credential definition private is required")
	}
	if options.CredentialOffer == nil {
		return nil, fmt.Errorf("credential offer is required")
	}
	if options.CredentialRequest == nil {
		return nil, fmt.Errorf("credential request is required")
	}
	
	handle, err := ffi.CreateCredential(
		options.CredentialDefinition.handle,
		options.CredentialDefinitionPrivate.handle,
		options.CredentialOffer.handle,
		options.CredentialRequest.handle,
		options.AttributeRawValues,
		options.AttributeEncodedValues,
		options.RevocationConfig,
	)
	if err != nil {
		return nil, err
	}
	
	return &Credential{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

/// @notice Options for processing a received credential
/// @dev Contains all necessary components to process and store a credential
type ProcessCredentialOptions struct {
	Credential                  *Credential                    /// @notice The credential to process
	CredentialRequestMetadata   *CredentialRequestMetadata    /// @notice Metadata from the credential request
	LinkSecret                  *LinkSecret                    /// @notice The prover's link secret
	CredentialDefinition        *CredentialDefinition         /// @notice The credential definition
	RevocationRegistryDefinition *RevocationRegistryDefinition /// @notice Optional revocation registry definition
}

/// @notice Processes a received credential for storage
/// @dev Validates and prepares the credential for secure storage
func ProcessCredential(options ProcessCredentialOptions) (*Credential, error) {
	if options.Credential == nil {
		return nil, fmt.Errorf("credential is required")
	}
	if options.CredentialRequestMetadata == nil {
		return nil, fmt.Errorf("credential request metadata is required")
	}
	if options.LinkSecret == nil {
		return nil, fmt.Errorf("link secret is required")
	}
	if options.CredentialDefinition == nil {
		return nil, fmt.Errorf("credential definition is required")
	}
	
	var revRegDef *ffi.ObjectHandle
	if options.RevocationRegistryDefinition != nil {
		revRegDef = options.RevocationRegistryDefinition.handle
	}
	
	handle, err := ffi.ProcessCredential(
		options.Credential.handle,
		options.CredentialRequestMetadata.handle,
		options.LinkSecret.Value,
		options.CredentialDefinition.handle,
		revRegDef,
	)
	if err != nil {
		return nil, err
	}
	
	return &Credential{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

// CredentialFromJSON creates a credential from JSON
func CredentialFromJSON(jsonData interface{}) (*Credential, error) {
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
	
	handle, err := ffi.ObjectFromJSON("Credential", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &Credential{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

// GetRevocationRegistryIndex returns the revocation registry index if the credential is revocable
func (c *Credential) GetRevocationRegistryIndex() (*uint32, error) {
	credJSON, err := c.ToJSON()
	if err != nil {
		return nil, err
	}
	
	if revRegIndex, ok := credJSON["rev_reg_index"].(float64); ok {
		index := uint32(revRegIndex)
		return &index, nil
	}
	
	return nil, nil
}