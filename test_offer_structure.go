package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
)

func main() {
	// Create a test schema
	schema, err := anoncreds.CreateSchema(anoncreds.CreateSchemaOptions{
		Name:           "TestSchema",
		Version:        "1.0",
		IssuerID:       "did:test:issuer",
		AttributeNames: []string{"name", "age"},
	})
	if err != nil {
		log.Fatalf("create schema: %v", err)
	}
	defer schema.Clear()

	// Create credential definition
	result, err := anoncreds.CreateCredentialDefinition(anoncreds.CreateCredentialDefinitionOptions{
		SchemaID:          "schema:test:1",
		Schema:            schema,
		IssuerID:          "did:test:issuer",
		Tag:               "default",
		SignatureType:     "CL",
		SupportRevocation: false,
	})
	if err != nil {
		log.Fatalf("create cred def: %v", err)
	}
	defer result.CredentialDefinition.Clear()
	defer result.CredentialDefinitionPrivate.Clear()
	defer result.KeyCorrectnessProof.Clear()

	// Create offer
	offer, err := anoncreds.CreateCredentialOffer(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               "schema:test:1",
		CredentialDefinitionID: "creddef:test:1",
		KeyCorrectnessProof:    result.KeyCorrectnessProof,
	})
	if err != nil {
		log.Fatalf("create offer: %v", err)
	}
	defer offer.Clear()

	// Get the raw JSON string from C API
	jsonString, err := offer.ToJSONString()
	if err != nil {
		log.Fatalf("to json string: %v", err)
	}

	fmt.Println("Raw JSON from C API:")
	fmt.Println(jsonString)
	fmt.Println()

	// Pretty print it
	var m map[string]interface{}
	json.Unmarshal([]byte(jsonString), &m)
	pretty, _ := json.MarshalIndent(m, "", "  ")
	fmt.Println("Pretty printed:")
	fmt.Println(string(pretty))

	// Test if we can re-parse it
	fmt.Println("\nTrying to re-parse the JSON...")
	offer2, err := anoncreds.CredentialOfferFromJSON(jsonString)
	if err != nil {
		log.Printf("Failed to re-parse: %v", err)
	} else {
		offer2.Clear()
		fmt.Println("Successfully re-parsed!")
	}
}