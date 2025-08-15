package anoncreds

/// @notice Transforms xr_cap from array format to object format for compatibility
/// @param offerData The credential offer data containing key_correctness_proof
func TransformXrCapToObject(offerData map[string]interface{}) {
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

/// @notice Creates a credential offer compatible with Credo-TS format
/// @param options The options for creating the credential offer
/// @return A map containing the credential offer data and any error encountered
func CreateCredentialOfferForCredoTS(options CreateCredentialOfferOptions) (map[string]interface{}, error) {
	// Create the offer using the C API
	offer, err := CreateCredentialOffer(options)
	if err != nil {
		return nil, err
	}
	defer offer.Clear()
	
	// Get the JSON as-is from C API - do not transform
	offerJSON, err := offer.ToJSON()
	if err != nil {
		return nil, err
	}
	
	// Return the offer without any transformations
	// The anoncreds library in Credo-TS expects the exact format from the C API
	return offerJSON, nil
}