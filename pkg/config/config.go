package config

type Config struct {
	StorageBaseUrl  string
	VerifierBaseUrl string
	OrderBaseUrl    string
	VerifierAuthPK  string
}

func Demo() *Config {
	return &Config{
		StorageBaseUrl:  "https://storage-demo.brij.fi/",
		VerifierBaseUrl: "https://verifier-demo.brij.fi/",
		OrderBaseUrl:    "https://orders-demo.brij.fi/",
		VerifierAuthPK:  "HHV5joB6D4c2pigVZcQ9RY5suDMvAiHBLLBCFqmWuM4E",
	}
}

const (
	AudStorage  = "storage.brij.fi"
	AudOrders   = "orders.brij.fi"
	AudVerifier = "verifier.brij.fi"
)
