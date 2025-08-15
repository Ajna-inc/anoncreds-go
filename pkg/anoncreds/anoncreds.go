package anoncreds

import (
	"encoding/json"
	"fmt"

	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Main API for anonymous credentials operations
/// @dev Provides core functionality for managing anonymous credentials
type Anoncreds struct{}

/// @notice Creates a new Anoncreds instance
/// @return A pointer to the new Anoncreds instance
func New() *Anoncreds {
	return &Anoncreds{}
}

/// @notice Generates a new nonce for proof requests
/// @return A string containing the nonce and any error encountered
func (a *Anoncreds) GenerateNonce() (string, error) {
	return ffi.GenerateNonce()
}

/// @dev Wrapper for FFI object handle to manage memory safely
type ObjectHandle struct {
	handle *ffi.ObjectHandle
}

/// @notice Frees the underlying FFI object handle
/// @dev Should be called when the handle is no longer needed to prevent memory leaks
func (o *ObjectHandle) Clear() {
	if o != nil && o.handle != nil {
		o.handle.Clear()
	}
}

/// @notice Converts the object handle to a JSON map
/// @return A map containing the JSON data and any error encountered
func (o *ObjectHandle) ToJSON() (map[string]interface{}, error) {
	if o == nil || o.handle == nil {
		return nil, fmt.Errorf("nil handle")
	}
	
	jsonStr, err := ffi.ObjectToJSON(o.handle)
	if err != nil {
		return nil, err
	}
	
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		return nil, err
	}
	
	return result, nil
}

/// @notice Converts the object handle to a JSON string
/// @return A string containing the JSON representation and any error encountered
func (o *ObjectHandle) ToJSONString() (string, error) {
	if o == nil || o.handle == nil {
		return "", fmt.Errorf("nil handle")
	}
	
	return ffi.ObjectToJSON(o.handle)
}