package evttypes

func PermissionDefIssue(threshold int) *PermissionDef {
	return &PermissionDef{
		Name:      "issue",
		Threshold: threshold,
		//Authorizers: make([]AuthorizerWeight, 0),
	}
}

func PermissionDefManage(threshold int) *PermissionDef {
	return &PermissionDef{
		Name:      "manage",
		Threshold: threshold,
		//Authorizers: make([]AuthorizerWeight, 0),
	}
}

func PermissionDefTranfer(threshold int) *PermissionDef {
	return &PermissionDef{
		Name:      "transfer",
		Threshold: threshold,
		//Authorizers: make([]AuthorizerWeight, 0),
	}
}

func (pd *PermissionDef) AddAuthorizer(weight *AuthorizerWeight) {
	pd.Authorizers = append(pd.Authorizers, *weight)
}
