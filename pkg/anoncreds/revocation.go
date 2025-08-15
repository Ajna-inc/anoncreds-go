package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Revocation Types and Operations
/// @dev Core functionality for managing credential revocation

/// @notice Represents a registry for tracking revoked credentials
/// @dev Wraps the underlying FFI object handle for revocation registry definitions
type RevocationRegistryDefinition struct {
	*ObjectHandle
}

/// @notice Private data for a revocation registry
/// @dev Contains sensitive key material that must be kept secure
type RevocationRegistryDefinitionPrivate struct {
	*ObjectHandle
}

/// @notice List tracking the current revocation status of credentials
/// @dev Used to verify if a credential has been revoked
type RevocationStatusList struct {
	*ObjectHandle
}

/// @notice Creates a revocation registry definition from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A revocation registry definition object and any error encountered
/// @dev Supports multiple input formats for flexibility
func RevocationRegistryDefinitionFromJSON(jsonData interface{}) (*RevocationRegistryDefinition, error) {
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
	
	handle, err := ffi.ObjectFromJSON("RevocationRegistryDefinition", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &RevocationRegistryDefinition{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

/// @notice Creates a revocation status list from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A revocation status list object and any error encountered
/// @dev Supports multiple input formats for flexibility
func RevocationStatusListFromJSON(jsonData interface{}) (*RevocationStatusList, error) {
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
	
	handle, err := ffi.ObjectFromJSON("RevocationStatusList", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &RevocationStatusList{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}