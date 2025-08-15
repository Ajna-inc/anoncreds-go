package tests

import (
	"encoding/json"
	"testing"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
)

func TestFullCredentialFlow(t *testing.T) {
	// 1. Issuer creates schema
	schema, err := anoncreds.CreateSchema(anoncreds.CreateSchemaOptions{
		Name:           "test-schema",
		Version:        "1.0",
		IssuerID:       "did:example:issuer",
		AttributeNames: []string{"name", "age", "height"},
	})
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}
	defer schema.Clear()

	// 2. Issuer creates credential definition
	credDefResult, err := anoncreds.CreateCredentialDefinition(anoncreds.CreateCredentialDefinitionOptions{
		SchemaID:          "schema:id:1234",
		Schema:            schema,
		IssuerID:          "did:example:issuer",
		Tag:               "default",
		SignatureType:     "CL",
		SupportRevocation: false,
	})
	if err != nil {
		t.Fatalf("Failed to create credential definition: %v", err)
	}
	defer credDefResult.CredentialDefinition.Clear()
	defer credDefResult.CredentialDefinitionPrivate.Clear()
	defer credDefResult.KeyCorrectnessProof.Clear()

	// 3. Issuer creates credential offer
	offer, err := anoncreds.CreateCredentialOffer(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               "schema:id:1234",
		CredentialDefinitionID: "creddef:id:5678",
		KeyCorrectnessProof:    credDefResult.KeyCorrectnessProof,
	})
	if err != nil {
		t.Fatalf("Failed to create credential offer: %v", err)
	}
	defer offer.Clear()

	// 4. Holder creates link secret
	linkSecret, err := anoncreds.CreateLinkSecret()
	if err != nil {
		t.Fatalf("Failed to create link secret: %v", err)
	}
	// Link secret is a string, no need to clear

	// 5. Holder creates credential request
	credReqResult, err := anoncreds.CreateCredentialRequest(anoncreds.CreateCredentialRequestOptions{
		Entropy:              "some-entropy-value",
		ProverDID:            nil,
		CredentialDefinition: credDefResult.CredentialDefinition,
		LinkSecret:           linkSecret,
		LinkSecretID:         "link-secret-id",
		CredentialOffer:      offer,
	})
	if err != nil {
		t.Fatalf("Failed to create credential request: %v", err)
	}
	defer credReqResult.CredentialRequest.Clear()
	defer credReqResult.CredentialRequestMetadata.Clear()

	// 6. Issuer creates credential
	credential, err := anoncreds.CreateCredential(anoncreds.CreateCredentialOptions{
		CredentialDefinition:        credDefResult.CredentialDefinition,
		CredentialDefinitionPrivate: credDefResult.CredentialDefinitionPrivate,
		CredentialOffer:            offer,
		CredentialRequest:          credReqResult.CredentialRequest,
		AttributeRawValues: map[string]string{
			"name":   "Alice",
			"age":    "28",
			"height": "175",
		},
	})
	if err != nil {
		t.Fatalf("Failed to create credential: %v", err)
	}
	defer credential.Clear()

	// 7. Holder processes credential
	processedCred, err := anoncreds.ProcessCredential(anoncreds.ProcessCredentialOptions{
		Credential:                credential,
		CredentialRequestMetadata: credReqResult.CredentialRequestMetadata,
		LinkSecret:                linkSecret,
		CredentialDefinition:      credDefResult.CredentialDefinition,
	})
	if err != nil {
		t.Fatalf("Failed to process credential: %v", err)
	}
	defer processedCred.Clear()

	// Verify the processed credential
	credJSON, err := processedCred.ToJSON()
	if err != nil {
		t.Fatalf("Failed to get credential JSON: %v", err)
	}

	// Check that credential has expected structure
	if _, ok := credJSON["schema_id"]; !ok {
		t.Error("Processed credential missing schema_id")
	}
	if _, ok := credJSON["cred_def_id"]; !ok {
		t.Error("Processed credential missing cred_def_id")
	}
	if _, ok := credJSON["signature"]; !ok {
		t.Error("Processed credential missing signature")
	}
	if values, ok := credJSON["values"].(map[string]interface{}); ok {
		if _, hasName := values["name"]; !hasName {
			t.Error("Credential missing 'name' attribute")
		}
		if _, hasAge := values["age"]; !hasAge {
			t.Error("Credential missing 'age' attribute")
		}
		if _, hasHeight := values["height"]; !hasHeight {
			t.Error("Credential missing 'height' attribute")
		}
	} else {
		t.Error("Credential missing values")
	}

	jsonBytes, _ := json.MarshalIndent(credJSON, "", "  ")
	t.Logf("Processed credential JSON:\n%s", string(jsonBytes))
}

func TestCredentialOfferTransformation(t *testing.T) {
	// Test that we can handle the xr_cap transformation at the application layer
	kcpJSON := map[string]interface{}{
		"c": "some_value",
		"xr_cap": []interface{}{
			[]interface{}{"master_secret", "value1"},
			[]interface{}{"name", "value2"},
			[]interface{}{"height", "value3"},
		},
		"xz_cap": "some_other_value",
	}
	
	// Create KCP from JSON
	kcp, err := anoncreds.KeyCorrectnessProofFromJSON(kcpJSON)
	if err != nil {
		t.Fatalf("Failed to create KCP from JSON: %v", err)
	}
	defer kcp.Clear()
	
	// Create offer using the KCP
	offer, err := anoncreds.CreateCredentialOffer(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               "schema:test:id",
		CredentialDefinitionID: "creddef:test:id",
		KeyCorrectnessProof:    kcp,
	})
	if err != nil {
		t.Fatalf("Failed to create offer with JSON KCP: %v", err)
	}
	defer offer.Clear()
	
	// Get the offer JSON
	offerJSON, err := offer.ToJSON()
	if err != nil {
		t.Fatalf("Failed to get offer JSON: %v", err)
	}
	
	// Transform xr_cap from array to object at application layer
	transformXrCapToObject(offerJSON)
	
	// Verify transformation
	if kcp, ok := offerJSON["key_correctness_proof"].(map[string]interface{}); ok {
		if xrCap, ok := kcp["xr_cap"].(map[string]interface{}); ok {
			if xrCap["master_secret"] == nil {
				t.Error("xr_cap missing master_secret after transformation")
			}
			if xrCap["name"] == nil {
				t.Error("xr_cap missing name after transformation")
			}
			if xrCap["height"] == nil {
				t.Error("xr_cap missing height after transformation")
			}
			t.Log("xr_cap successfully transformed to object format")
		} else {
			t.Error("xr_cap is not an object after transformation")
		}
	}
	
	jsonBytes, _ := json.MarshalIndent(offerJSON, "", "  ")
	t.Logf("Transformed offer JSON:\n%s", string(jsonBytes))
}

// transformXrCapToObject transforms xr_cap from array format to object format
// This should be used at the application layer when sending to Credo-TS
func transformXrCapToObject(offerData map[string]interface{}) {
	if kcp, ok := offerData["key_correctness_proof"].(map[string]interface{}); ok {
		if xrCapArray, ok := kcp["xr_cap"].([]interface{}); ok {
			xrCapObj := make(map[string]interface{})
			for _, item := range xrCapArray {
				if pair, ok := item.([]interface{}); ok && len(pair) == 2 {
					if key, ok := pair[0].(string); ok {
						xrCapObj[key] = pair[1]
					}
				}
			}
			kcp["xr_cap"] = xrCapObj
		}
	}
}