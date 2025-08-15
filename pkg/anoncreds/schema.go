package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Schema Types and Operations
/// @dev Core functionality for managing credential schemas

/// @notice Represents a credential schema that defines attribute structure
/// @dev Wraps the underlying FFI object handle for schemas
type Schema struct {
	*ObjectHandle
}

/// @notice Configuration options for creating a new schema
/// @dev All fields are required and must be properly formatted
type CreateSchemaOptions struct {
	Name           string   `json:"name"`           /// @notice Schema name
	Version        string   `json:"version"`        /// @notice Schema version
	IssuerID       string   `json:"issuer_id"`     /// @notice ID of the issuer
	AttributeNames []string `json:"attr_names"`     /// @notice List of attribute names
}

/// @notice Creates a new credential schema from the provided options
/// @param options Configuration options for the schema
/// @return A new schema object and any error encountered
/// @dev Validates and creates a schema that can be used for credential definitions
func CreateSchema(options CreateSchemaOptions) (*Schema, error) {
	handle, err := ffi.CreateSchema(
		options.Name,
		options.IssuerID,
		options.Version,
		options.AttributeNames,
	)
	if err != nil {
		return nil, err
	}
	
	return &Schema{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}

/// @notice Creates a schema from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A schema object and any error encountered
/// @dev Supports multiple input formats for flexibility
func SchemaFromJSON(jsonData interface{}) (*Schema, error) {
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
	
	handle, err := ffi.ObjectFromJSON("Schema", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &Schema{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}