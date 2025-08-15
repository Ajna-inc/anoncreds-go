package ffi

/*
#include "libanoncreds.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

/// @notice Creates a new link secret for the prover
/// @return The generated link secret string and any error encountered
/// @dev Link secrets are used to maintain continuity between different credentials for the same identity
func CreateLinkSecret() (string, error) {
	var linkSecretPtr *C.char
	
	code := C.anoncreds_create_link_secret(&linkSecretPtr)
	
	if err := handleError(code); err != nil {
		return "", err
	}
	
	if linkSecretPtr != nil {
		defer C.anoncreds_string_free(linkSecretPtr)
		return C.GoString(linkSecretPtr), nil
	}
	
	return "", fmt.Errorf("failed to create link secret")
}

/// @notice Creates a credential request for the prover
/// @dev This function generates a request for a credential based on an offer from an issuer
func CreateCredentialRequest(
	entropy string,
	proverDid *string, // optional
	credDef *ObjectHandle,
	linkSecret string,
	linkSecretId string,
	credOffer *ObjectHandle,
) (*ObjectHandle, *ObjectHandle, error) {
	cEntropy := C.CString(entropy)
	defer C.free(unsafe.Pointer(cEntropy))
	
	cLinkSecretId := C.CString(linkSecretId)
	defer C.free(unsafe.Pointer(cLinkSecretId))
	
	var cProverDid C.FfiStr
	if proverDid != nil && *proverDid != "" {
		cDid := C.CString(*proverDid)
		defer C.free(unsafe.Pointer(cDid))
		cProverDid = C.FfiStr(cDid)
	}
	
	var credRequestHandle C.ObjectHandle
	var credRequestMetadataHandle C.ObjectHandle
	
	cLinkSecret := C.CString(linkSecret)
	defer C.free(unsafe.Pointer(cLinkSecret))
	
	code := C.anoncreds_create_credential_request(
		C.FfiStr(cEntropy),
		cProverDid,
		credDef.GetHandle(),
		C.FfiStr(cLinkSecret),
		C.FfiStr(cLinkSecretId),
		credOffer.GetHandle(),
		&credRequestHandle,
		&credRequestMetadataHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, nil, err
	}
	
	return NewObjectHandle(credRequestHandle), 
		NewObjectHandle(credRequestMetadataHandle), 
		nil
}

/// @notice Processes a received credential for storage
/// @dev Validates and prepares the credential for storage and future use
func ProcessCredential(
	credential *ObjectHandle,
	credRequestMetadata *ObjectHandle,
	linkSecret string,
	credDef *ObjectHandle,
	revRegDef *ObjectHandle, // optional
) (*ObjectHandle, error) {
	var processedCredHandle C.ObjectHandle
	
	var revRegDefHandle C.ObjectHandle = 0
	if revRegDef != nil {
		revRegDefHandle = revRegDef.GetHandle()
	}
	
	cLinkSecret := C.CString(linkSecret)
	defer C.free(unsafe.Pointer(cLinkSecret))
	
	code := C.anoncreds_process_credential(
		credential.GetHandle(),
		credRequestMetadata.GetHandle(),
		C.FfiStr(cLinkSecret),
		credDef.GetHandle(),
		revRegDefHandle,
		&processedCredHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, err
	}
	
	return NewObjectHandle(processedCredHandle), nil
}

/// @notice Creates a verifiable presentation from credentials
/// @dev Generates a presentation that proves possession of credentials while revealing only specified attributes
func CreatePresentation(
	presRequest *ObjectHandle,
	credentials []PresentCredential,
	credDefs map[string]*ObjectHandle,
	schemas map[string]*ObjectHandle,
	linkSecret string,
	credentialsProve []CredentialProve,
	selfAttestedAttrs map[string]string,
) (*ObjectHandle, error) {
	// Placeholder for presentation creation implementation
	var presentationHandle C.ObjectHandle
	
	return NewObjectHandle(presentationHandle), nil
}

/// @dev Represents a credential to be included in a presentation
/// @notice Contains the credential and optional revocation state
type PresentCredential struct {
	Credential    *ObjectHandle
	Timestamp     *int64
	RevState      *ObjectHandle
}

/// @dev Specifies what attributes to reveal in a presentation
/// @notice Defines the proof requirements for a specific credential
type CredentialProve struct {
	EntryIndex  int
	Referent    string
	IsPredicate bool
	Reveal      bool
}