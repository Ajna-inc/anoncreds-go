package ffi

/*
#cgo CFLAGS: -I${SRCDIR}
#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/libanoncreds.a -L/usr/local/opt/openssl/lib -lssl -lcrypto -lc++ -framework CoreFoundation -framework Security -framework SystemConfiguration
#cgo darwin,arm64 LDFLAGS: ${SRCDIR}/libanoncreds.a -L/opt/homebrew/opt/openssl/lib -lssl -lcrypto -lc++ -framework CoreFoundation -framework Security -framework SystemConfiguration
#cgo linux LDFLAGS: ${SRCDIR}/libanoncreds.a -ldl -lrt -lm -lpthread -lssl -lcrypto
#include "libanoncreds.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// ErrorCode represents anoncreds error codes
type ErrorCode int

const (
	Success               ErrorCode = 0
	Input                 ErrorCode = 1
	IOError               ErrorCode = 2
	InvalidState          ErrorCode = 3
	Unexpected            ErrorCode = 4
	CredentialRevoked     ErrorCode = 5
	InvalidUserRevocId    ErrorCode = 6
	ProofRejected         ErrorCode = 7
	RevocationRegistryFull ErrorCode = 8
)

// ObjectHandle represents a handle to an anoncreds object
type ObjectHandle struct {
	handle C.ObjectHandle
}

// NewObjectHandle creates a new object handle
func NewObjectHandle(handle C.ObjectHandle) *ObjectHandle {
	return &ObjectHandle{handle: handle}
}

// Clear frees the object handle
func (o *ObjectHandle) Clear() {
	if o != nil && o.handle != 0 {
		C.anoncreds_object_free(o.handle)
		o.handle = 0
	}
}

// GetHandle returns the raw handle
func (o *ObjectHandle) GetHandle() C.ObjectHandle {
	if o == nil {
		return 0
	}
	return o.handle
}

// GetLastError returns the last error message
func GetLastError() string {
	var errorPtr *C.char
	code := C.anoncreds_get_current_error(&errorPtr)
	if code != 0 && errorPtr != nil {
		defer C.anoncreds_string_free(errorPtr)
		return C.GoString(errorPtr)
	}
	return ""
}

// handleError checks for errors and returns Go error
func handleError(code C.ErrorCode) error {
	if code != C.Success {
		errMsg := GetLastError()
		return fmt.Errorf("anoncreds error %d: %s", code, errMsg)
	}
	return nil
}

// createByteBuffer creates a ByteBuffer from a Go string
func createByteBuffer(s string) C.struct_ByteBuffer {
	data := C.CString(s)
	return C.struct_ByteBuffer{
		len:  C.int64_t(len(s)),
		data: (*C.uint8_t)(unsafe.Pointer(data)),
	}
}

// freeByteBuffer frees a ByteBuffer
func freeByteBuffer(bb C.struct_ByteBuffer) {
	if bb.data != nil {
		C.free(unsafe.Pointer(bb.data))
	}
}

// ObjectFromJSON creates an object from JSON
func ObjectFromJSON(objType string, json string) (*ObjectHandle, error) {
	bb := createByteBuffer(json)
	defer freeByteBuffer(bb)
	
	var handle C.ObjectHandle
	var code C.ErrorCode
	
	switch objType {
	case "Schema":
		code = C.anoncreds_schema_from_json(bb, &handle)
	case "CredentialDefinition":
		code = C.anoncreds_credential_definition_from_json(bb, &handle)
	case "CredentialOffer":
		code = C.anoncreds_credential_offer_from_json(bb, &handle)
	case "CredentialRequest":
		code = C.anoncreds_credential_request_from_json(bb, &handle)
	case "Credential":
		code = C.anoncreds_credential_from_json(bb, &handle)
	case "KeyCorrectnessProof":
		code = C.anoncreds_key_correctness_proof_from_json(bb, &handle)
	case "CredentialRequestMetadata":
		code = C.anoncreds_credential_request_metadata_from_json(bb, &handle)
	case "RevocationRegistryDefinition":
		code = C.anoncreds_revocation_registry_definition_from_json(bb, &handle)
	case "RevocationStatusList":
		code = C.anoncreds_revocation_status_list_from_json(bb, &handle)
	case "PresentationRequest":
		code = C.anoncreds_presentation_request_from_json(bb, &handle)
	case "Presentation":
		code = C.anoncreds_presentation_from_json(bb, &handle)
	default:
		return nil, fmt.Errorf("unknown object type: %s", objType)
	}
	
	if err := handleError(code); err != nil {
		return nil, err
	}
	
	return NewObjectHandle(handle), nil
}

// ObjectToJSON converts an object to JSON
func ObjectToJSON(handle *ObjectHandle) (string, error) {
	if handle == nil {
		return "", fmt.Errorf("nil handle")
	}
	
	var bb C.struct_ByteBuffer
	code := C.anoncreds_object_get_json(handle.handle, &bb)
	
	if err := handleError(code); err != nil {
		return "", err
	}
	
	if bb.data != nil {
		// Convert to Go string
		jsonBytes := C.GoBytes(unsafe.Pointer(bb.data), C.int(bb.len))
		// Free the buffer
		C.anoncreds_buffer_free(bb)
		return string(jsonBytes), nil
	}
	
	return "", fmt.Errorf("failed to get JSON")
}

// GenerateNonce generates a new nonce
func GenerateNonce() (string, error) {
	var noncePtr *C.char
	code := C.anoncreds_generate_nonce(&noncePtr)
	
	if err := handleError(code); err != nil {
		return "", err
	}
	
	if noncePtr != nil {
		defer C.anoncreds_string_free(noncePtr)
		return C.GoString(noncePtr), nil
	}
	
	return "", fmt.Errorf("failed to generate nonce")
}