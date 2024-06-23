package main

import "github.com/jindal2209/msal-token-validator/token_validator"

func main() {
	// token_validator.ValidateToken("", token_validator.TokenTypeIdToken)
	c, _ := token_validator.NewClient(&token_validator.Config{
		ApplicationId: "MSAL_APPLICATION_ID",
		TenantId:      "MSAL_TENANT_ID",
	})

	c.ValidateToken("msal token", token_validator.TokenTypeIdToken)
}
