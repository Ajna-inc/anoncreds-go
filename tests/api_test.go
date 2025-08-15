package tests

import (
	"encoding/json"
	"testing"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
)

func TestCreateCredentialOffer(t *testing.T) {
	// Create a schema
	schema, err := anoncreds.CreateSchema(anoncreds.CreateSchemaOptions{
		Name:           "test-schema",
		Version:        "1.0",
		IssuerID:       "mock:issuer",
		AttributeNames: []string{"name", "age", "height"},
	})
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}
	defer schema.Clear()

	// Create credential definition
	credDefResult, err := anoncreds.CreateCredentialDefinition(anoncreds.CreateCredentialDefinitionOptions{
		SchemaID:          "mock:schema:id",
		Schema:            schema,
		IssuerID:          "mock:issuer",
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

	// Create credential offer
	offer, err := anoncreds.CreateCredentialOffer(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               "mock:schema:id",
		CredentialDefinitionID: "mock:cred:def:id",
		KeyCorrectnessProof:    credDefResult.KeyCorrectnessProof,
	})
	if err != nil {
		t.Fatalf("Failed to create credential offer: %v", err)
	}
	defer offer.Clear()

	// Convert to JSON and verify structure
	offerJSON, err := offer.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert offer to JSON: %v", err)
	}

	// Check that offer has expected fields
	if _, ok := offerJSON["schema_id"]; !ok {
		t.Error("Offer missing schema_id")
	}
	if _, ok := offerJSON["cred_def_id"]; !ok {
		t.Error("Offer missing cred_def_id")
	}
	if _, ok := offerJSON["key_correctness_proof"]; !ok {
		t.Error("Offer missing key_correctness_proof")
	}
	
	// Verify key_correctness_proof structure
	kcp, ok := offerJSON["key_correctness_proof"].(map[string]interface{})
	if !ok {
		t.Fatal("key_correctness_proof is not a map")
	}
	
	// Check for xr_cap - raw C API returns it as an array
	if xrCap, ok := kcp["xr_cap"]; ok {
		if _, isArray := xrCap.([]interface{}); !isArray {
			t.Error("xr_cap should be an array from raw C API")
		}
		t.Log("xr_cap is correctly an array (raw C API format)")
	}
	
	// Log the JSON for debugging
	jsonBytes, _ := json.MarshalIndent(offerJSON, "", "  ")
	t.Logf("Credential offer JSON:\n%s", string(jsonBytes))
}

func TestCredentialOfferCompatibility(t *testing.T) {
	// Test that we can create an offer from JSON (like Credo-TS would send)
	kcpJSON := map[string]interface{}{
		"c": "some_value",
		"xr_cap": map[string]interface{}{
			"master_secret": "value1",
			"name":          "value2",
			"height":        "value3",
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
	
	// Verify the offer structure
	offerJSON, err := offer.ToJSON()
	if err != nil {
		t.Fatalf("Failed to convert offer to JSON: %v", err)
	}
	
	// The offer should have the correct structure for Credo-TS
	if offerJSON["schema_id"] != "schema:test:id" {
		t.Error("Incorrect schema_id")
	}
	if offerJSON["cred_def_id"] != "creddef:test:id" {
		t.Error("Incorrect cred_def_id")
	}
	
	jsonBytes, _ := json.MarshalIndent(offerJSON, "", "  ")
	t.Logf("Compatible offer JSON:\n%s", string(jsonBytes))
}