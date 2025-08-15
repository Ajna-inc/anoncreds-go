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

	// Get the credential definition JSON
	cdJSON, err := result.CredentialDefinition.ToJSONString()
	if err != nil {
		log.Fatalf("to json string: %v", err)
	}

	fmt.Println("Raw Credential Definition JSON from C API:")
	fmt.Println(cdJSON)
	fmt.Println()

	// Parse it to see structure
	var cdMap map[string]interface{}
	json.Unmarshal([]byte(cdJSON), &cdMap)
	
	fmt.Println("Credential Definition structure:")
	for key, val := range cdMap {
		fmt.Printf("  %s: %T\n", key, val)
	}
	
	// Check if "value" field exists
	if val, ok := cdMap["value"]; ok {
		fmt.Println("\n'value' field exists!")
		if valMap, ok := val.(map[string]interface{}); ok {
			fmt.Println("Value structure:")
			for k, v := range valMap {
				fmt.Printf("  %s: %T\n", k, v)
			}
		}
	} else {
		fmt.Println("\n'value' field DOES NOT exist!")
		fmt.Println("\nActual structure:")
		pretty, _ := json.MarshalIndent(cdMap, "", "  ")
		fmt.Println(string(pretty))
	}
}