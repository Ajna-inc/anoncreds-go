package anoncreds

import (
	"encoding/json"
	"fmt"
	
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Key Correctness Proof Types and Operations
/// @dev Core functionality for managing key correctness proofs

/// @notice Represents a proof that a credential definition's keys were generated correctly
/// @dev Wraps the underlying FFI object handle for key correctness proofs
type KeyCorrectnessProof struct {
	*ObjectHandle
}

/// @notice Creates a key correctness proof from its JSON representation
/// @param jsonData The JSON data as string, map, or byte array
/// @return A key correctness proof object and any error encountered
/// @dev Supports multiple input formats for flexibility
func KeyCorrectnessProofFromJSON(jsonData interface{}) (*KeyCorrectnessProof, error) {
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
	
	handle, err := ffi.ObjectFromJSON("KeyCorrectnessProof", jsonStr)
	if err != nil {
		return nil, err
	}
	
	return &KeyCorrectnessProof{
		ObjectHandle: &ObjectHandle{handle: handle},
	}, nil
}