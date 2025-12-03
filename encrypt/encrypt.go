package encrypt

type Encrypter interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(cipherData []byte) ([]byte, error)
}
