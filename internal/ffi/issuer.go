package ffi

/*
#include "libanoncreds.h"
#include <stdlib.h>
#include <string.h>
*/
import "C"
import (
	"unsafe"
)

/// @notice Creates a new credential schema
/// @param name The name of the schema
/// @param issuerId The ID of the issuer
/// @param version The version of the schema
/// @param attributeNames List of attribute names in the schema
/// @return A handle to the created schema and any error encountered
func CreateSchema(name, issuerId, version string, attributeNames []string) (*ObjectHandle, error) {
	// Convert to C strings
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	
	cIssuerId := C.CString(issuerId)
	defer C.free(unsafe.Pointer(cIssuerId))
	
	cVersion := C.CString(version)
	defer C.free(unsafe.Pointer(cVersion))
	
	// Convert attribute names to FfiStrList
	attrList := C.FfiStrList{}
	if len(attributeNames) > 0 {
		// Create C array of strings
		cAttrs := make([]*C.char, len(attributeNames))
		for i, attr := range attributeNames {
			cAttrs[i] = C.CString(attr)
		}
		defer func() {
			for _, cAttr := range cAttrs {
				C.free(unsafe.Pointer(cAttr))
			}
		}()
		
		// Create FfiStr array - FfiStr is just const char*
		ffiStrs := make([]C.FfiStr, len(attributeNames))
		for i, cAttr := range cAttrs {
			ffiStrs[i] = C.FfiStr(cAttr)
		}
		
		attrList.count = C.size_t(len(attributeNames))
		attrList.data = (*C.FfiStr)(unsafe.Pointer(&ffiStrs[0]))
	}
	
	var schemaHandle C.ObjectHandle
	code := C.anoncreds_create_schema(
		C.FfiStr(cName),
		C.FfiStr(cVersion),
		C.FfiStr(cIssuerId),
		attrList,
		&schemaHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, err
	}
	
	return NewObjectHandle(schemaHandle), nil
}

/// @notice Creates a new credential definition based on a schema
/// @param schemaId The ID of the schema to base the credential definition on
/// @param schema Handle to the schema object
/// @dev This function creates the credential definition structure that will be used for issuing credentials
func CreateCredentialDefinition(
	schemaId string,
	schema *ObjectHandle,
	issuerId string,
	tag string,
	signatureType string,
	supportRevocation bool,
) (*ObjectHandle, *ObjectHandle, *ObjectHandle, error) {
	cSchemaId := C.CString(schemaId)
	defer C.free(unsafe.Pointer(cSchemaId))
	
	cIssuerId := C.CString(issuerId)
	defer C.free(unsafe.Pointer(cIssuerId))
	
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))
	
	cSignatureType := C.CString(signatureType)
	defer C.free(unsafe.Pointer(cSignatureType))
	
	var credDefHandle C.ObjectHandle
	var credDefPrivateHandle C.ObjectHandle
	var keyProofHandle C.ObjectHandle
	
	var supportRev C.int8_t = 0
	if supportRevocation {
		supportRev = 1
	}
	
	code := C.anoncreds_create_credential_definition(
		C.FfiStr(cSchemaId),
		schema.GetHandle(),
		C.FfiStr(cTag),
		C.FfiStr(cIssuerId),
		C.FfiStr(cSignatureType),
		supportRev,
		&credDefHandle,
		&credDefPrivateHandle,
		&keyProofHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, nil, nil, err
	}
	
	return NewObjectHandle(credDefHandle), 
		NewObjectHandle(credDefPrivateHandle), 
		NewObjectHandle(keyProofHandle), 
		nil
}

// CreateCredentialOffer creates a credential offer
// This matches the Node.js wrapper's anoncreds_create_credential_offer
func CreateCredentialOffer(
	schemaId string,
	credentialDefinitionId string,
	keyCorrectnessProof *ObjectHandle,
) (*ObjectHandle, error) {
	cSchemaId := C.CString(schemaId)
	defer C.free(unsafe.Pointer(cSchemaId))
	
	cCredDefId := C.CString(credentialDefinitionId)
	defer C.free(unsafe.Pointer(cCredDefId))
	
	var credOfferHandle C.ObjectHandle
	
	code := C.anoncreds_create_credential_offer(
		C.FfiStr(cSchemaId),
		C.FfiStr(cCredDefId),
		keyCorrectnessProof.GetHandle(),
		&credOfferHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, err
	}
	
	return NewObjectHandle(credOfferHandle), nil
}

// CreateCredential creates a credential
func CreateCredential(
	credentialDefinition *ObjectHandle,
	credentialDefinitionPrivate *ObjectHandle,
	credentialOffer *ObjectHandle,
	credentialRequest *ObjectHandle,
	attributeRawValues map[string]string,
	attributeEncodedValues map[string]string,
	revocationConfig *RevocationConfig,
) (*ObjectHandle, error) {
	// Convert attribute names and values
	attrNames := make([]string, 0, len(attributeRawValues))
	attrRawVals := make([]string, 0, len(attributeRawValues))
	for name, value := range attributeRawValues {
		attrNames = append(attrNames, name)
		attrRawVals = append(attrRawVals, value)
	}
	
	// Create FfiStrList for names
	namesList := C.FfiStrList{}
	if len(attrNames) > 0 {
		cNames := make([]*C.char, len(attrNames))
		for i, name := range attrNames {
			cNames[i] = C.CString(name)
		}
		defer func() {
			for _, cName := range cNames {
				C.free(unsafe.Pointer(cName))
			}
		}()
		
		ffiNames := make([]C.FfiStr, len(attrNames))
		for i, cName := range cNames {
			ffiNames[i] = C.FfiStr(cName)
		}
		
		namesList.count = C.size_t(len(attrNames))
		namesList.data = (*C.FfiStr)(unsafe.Pointer(&ffiNames[0]))
	}
	
	// Create FfiStrList for raw values
	rawValuesList := C.FfiStrList{}
	if len(attrRawVals) > 0 {
		cVals := make([]*C.char, len(attrRawVals))
		for i, val := range attrRawVals {
			cVals[i] = C.CString(val)
		}
		defer func() {
			for _, cVal := range cVals {
				C.free(unsafe.Pointer(cVal))
			}
		}()
		
		ffiVals := make([]C.FfiStr, len(attrRawVals))
		for i, cVal := range cVals {
			ffiVals[i] = C.FfiStr(cVal)
		}
		
		rawValuesList.count = C.size_t(len(attrRawVals))
		rawValuesList.data = (*C.FfiStr)(unsafe.Pointer(&ffiVals[0]))
	}
	
	// Handle encoded values (optional)
	var encodedValuesList C.FfiStrList
	
	// Handle revocation config
	var revConfigPtr unsafe.Pointer
	if revocationConfig != nil {
		// Revocation config will be implemented in a future version
	}
	
	var credHandle C.ObjectHandle
	code := C.anoncreds_create_credential(
		credentialDefinition.GetHandle(),
		credentialDefinitionPrivate.GetHandle(),
		credentialOffer.GetHandle(),
		credentialRequest.GetHandle(),
		namesList,
		rawValuesList,
		encodedValuesList,
		(*C.struct_FfiCredRevInfo)(revConfigPtr),
		&credHandle,
	)
	
	if err := handleError(code); err != nil {
		return nil, err
	}
	
	return NewObjectHandle(credHandle), nil
}

// RevocationConfig holds revocation configuration
type RevocationConfig struct {
	RegistryDefinition        *ObjectHandle
	RegistryDefinitionPrivate *ObjectHandle
	StatusList               *ObjectHandle
	RegistryIndex            uint32
}