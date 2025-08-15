package anoncreds

import (
	"github.com/Ajna-inc/anoncreds-go/internal/ffi"
)

/// @title Link Secret Types and Operations
/// @dev Core functionality for managing link secrets (master secrets)

/// @notice Represents a link secret used to maintain continuity between credentials
/// @dev Stores the secret value as a string for simplicity
type LinkSecret struct {
	Value string /// @notice The actual link secret value
}

/// @notice Creates a new random link secret
/// @return A new link secret object and any error encountered
/// @dev Uses cryptographically secure random number generation
func CreateLinkSecret() (*LinkSecret, error) {
	secret, err := ffi.CreateLinkSecret()
	if err != nil {
		return nil, err
	}
	
	return &LinkSecret{
		Value: secret,
	}, nil
}

/// @notice Creates a link secret from an existing value
/// @param value The link secret value as a string
/// @return A new link secret object wrapping the provided value
/// @dev Use this when you have an existing link secret value
func LinkSecretFromValue(value string) *LinkSecret {
	return &LinkSecret{
		Value: value,
	}
}