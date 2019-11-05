package evtconfig

const version1 = "v1"

type Instance struct {
	HttpPath string
	Version  string
}

func New(httpPath string) *Instance {
	return &Instance{
		HttpPath: httpPath,
		Version:  version1,
	}
}
