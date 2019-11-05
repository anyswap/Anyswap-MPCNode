package evttypes

import "fmt"



func GroupOwnedAuthorizer() *AuthorizerWeight {
	return &AuthorizerWeight{
		Ref:    "[G] Owner",
		Weight: 1,
	}
}

func SingleAddressAuthorizer(address string) *AuthorizerWeight {
	return &AuthorizerWeight{
		Ref:    fmt.Sprintf("[A] %v", address),
		Weight: 1,
	}
}
