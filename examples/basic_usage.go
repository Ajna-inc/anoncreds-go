package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/Ajna-inc/anoncreds-go/pkg/anoncreds"
)

func main() {
	// Create a schema
	schema, err := anoncreds.CreateSchema(anoncreds.CreateSchemaOptions{
		Name:           "test-schema",
		Version:        "1.0",
		IssuerID:       "did:example:issuer",
		AttributeNames: []string{"name", "age", "height"},
	})
	if err != nil {
		log.Fatalf("Failed to create schema: %v", err)
	}
	defer schema.Clear()

	schemaJSON, _ := schema.ToJSON()
	fmt.Println("Schema created:")
	printJSON(schemaJSON)

	// Create credential definition
	credDefResult, err := anoncreds.CreateCredentialDefinition(anoncreds.CreateCredentialDefinitionOptions{
		SchemaID:          "schema:id:1234",
		Schema:            schema,
		IssuerID:          "did:example:issuer",
		Tag:               "default",
		SignatureType:     "CL",
		SupportRevocation: false,
	})
	if err != nil {
		log.Fatalf("Failed to create credential definition: %v", err)
	}
	defer credDefResult.CredentialDefinition.Clear()
	defer credDefResult.CredentialDefinitionPrivate.Clear()
	defer credDefResult.KeyCorrectnessProof.Clear()

	credDefJSON, _ := credDefResult.CredentialDefinition.ToJSON()
	fmt.Println("\nCredential Definition created:")
	printJSON(credDefJSON)

	// Create credential offer using the C API exactly like Node.js wrapper
	offer, err := anoncreds.CreateCredentialOffer(anoncreds.CreateCredentialOfferOptions{
		SchemaID:               "schema:id:1234",
		CredentialDefinitionID: "creddef:id:5678",
		KeyCorrectnessProof:    credDefResult.KeyCorrectnessProof,
	})
	if err != nil {
		log.Fatalf("Failed to create credential offer: %v", err)
	}
	defer offer.Clear()

	offerJSON, _ := offer.ToJSON()
	fmt.Println("\nCredential Offer created (raw from C API):")
	printJSON(offerJSON)
	
	// Note: The xr_cap field comes as an array from the C API
	// This is the same behavior as the Node.js wrapper's native bindings
	// Any transformation should be done at the application layer if needed
}

func printJSON(data interface{}) {
	bytes, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(bytes))
}