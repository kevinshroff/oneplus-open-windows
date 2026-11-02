package main

const ioctlStatus uint32 = 0x226a40
const ioctlRead uint32 = 0x22ea44
const ioctlResult uint32 = 0x226a48

func encodeRequest(nonce uint64) []byte {
	b := make([]byte, 32)
	le.PutUint32(b, 32)
	le.PutUint32(b[4:], 1)
	le.PutUint64(b[8:], 0x314c47343631474f)
	le.PutUint64(b[16:], nonce)
	return b
}
