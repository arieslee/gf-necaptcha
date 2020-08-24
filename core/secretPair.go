package core

type SecretPair struct {
	SecretId  string
	SecretKey string
}

func NewSecretPair(secretId string, secretKey string) *SecretPair {
	return &SecretPair{
		SecretId:  secretId,
		SecretKey: secretKey,
	}
}
