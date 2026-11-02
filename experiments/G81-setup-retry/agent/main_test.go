package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestSignedJobIsolation(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	j := Job{ID: "one", Node: "phone", Session: "current", Action: "probe", Timeout: 30}
	b, _ := json.Marshal(j)
	e := Envelope{b, ed25519.Sign(key, b)}
	if _, err := verify(e, pub, "phone", "current"); err != nil {
		t.Fatal(err)
	}
	for _, x := range []struct{ node, session string }{{"host", "current"}, {"phone", "previous"}} {
		if _, err := verify(e, pub, x.node, x.session); err == nil {
			t.Fatal("wrong worker/session accepted")
		}
	}
	seen := map[string]bool{}
	if _, err := verifyFresh(e, pub, "phone", "current", seen); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyFresh(e, pub, "phone", "current", seen); err == nil {
		t.Fatal("same-session replay accepted")
	}
	e.Payload[0] ^= 1
	if _, err := verify(e, pub, "phone", "current"); err == nil {
		t.Fatal("tampered job accepted")
	}
}

func TestTLSCertificatePin(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("pinned")) }))
	defer s.Close()
	h := sha256.Sum256(s.Certificate().Raw)
	c := Config{URL: s.URL, CertificateSHA256: hex.EncodeToString(h[:])}
	cl, err := clientFor(c)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cl.Get(s.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	h[0] ^= 1
	c.CertificateSHA256 = hex.EncodeToString(h[:])
	cl, err = clientFor(c)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err = cl.Get(s.URL); err == nil {
		resp.Body.Close()
		t.Fatal("wrong TLS certificate accepted")
	}
}
func TestPayloadIntegrityAndBoundary(t *testing.T) {
	dir := t.TempDir()
	c := Config{PayloadDir: dir}
	j := Job{ID: "put", Action: "put", Path: "hello.bin", Data: []byte("roundtrip"), SHA256: "wrong"}
	if r := execute(c, j); r.Status != "error" {
		t.Fatal("bad hash accepted")
	}
	j.SHA256 = digest(j.Data)
	if r := execute(c, j); r.Status != "ok" {
		t.Fatal(r)
	}
	j.Action = "get"
	j.Path = filepath.Join(dir, "hello.bin")
	r := execute(c, j)
	if string(r.Data) != "roundtrip" || r.SHA256 != j.SHA256 {
		t.Fatal(r)
	}
	if _, err := payloadPath(c, "../escape"); err == nil {
		t.Fatal("parent path accepted")
	}
	if _, err := payloadPath(c, filepath.Join(filepath.Dir(dir), "outside")); err == nil {
		t.Fatal("outside absolute path accepted")
	}
}
func TestInterruptedJournalSurvives(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pending.json")
	r := Result{ID: "x", Status: "interrupted_unknown"}
	if err := atomicJSON(p, r); err != nil {
		t.Fatal(err)
	}
	r.Status = "ok"
	if err := atomicJSON(p, r); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got Result
	if json.Unmarshal(b, &got) != nil || got.Status != "ok" {
		t.Fatal(string(b))
	}
}
