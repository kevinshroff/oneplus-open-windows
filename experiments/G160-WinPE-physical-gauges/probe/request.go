package main

func encodeRequest(nonce uint64) []byte {
	b := make([]byte, 32)
	le.PutUint32(b, 32)
	le.PutUint32(b[4:], 1)
	le.PutUint64(b[8:], 0x315147303631474f)
	le.PutUint64(b[16:], nonce)
	return b
}
