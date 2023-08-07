package certsort

type rawCert []byte
type rawCerts []rawCert

// NewRawCert returns new RawCerts from given strings.
// The strings must be PEM-encoded.
// The order of the certificates is not important.
func NewRawCerts(certs ...string) rawCerts {
	var result rawCerts
	for _, cert := range certs {
		result = append(result, []byte(cert))
	}
	return result
}

func (r rawCerts) ByteArray() [][]byte {
	var result [][]byte
	for _, cert := range r {
		result = append(result, []byte(cert))
	}
	return result
}

func (r rawCerts) Append(cert ...string) rawCerts {
	for _, c := range cert {
		r = append(r, []byte(c))
	}
	return r
}
