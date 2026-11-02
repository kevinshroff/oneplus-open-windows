package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestG70RejectsPreviousQualifiedG68Pair(t *testing.T) {
	p := WIMPlan{Version: "G21-trial-wim-v1", Name: trialWIMName,
		BeforeBytes: 594423099, AfterBytes: 595963755,
		BeforeSHA: "cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7",
		AfterSHA:  "de32242eb883ed45d1d29db52190ef5161da6845cccbad40c7cf821a0866b9dc"}
	if validateRAMWIMPair(p) == nil {
		t.Fatal("old G68 pair accepted")
	}
	p.BeforeBytes, p.AfterBytes = p.AfterBytes, p.BeforeBytes
	p.BeforeSHA, p.AfterSHA = p.AfterSHA, p.BeforeSHA
	if validateRAMWIMPair(p) == nil {
		t.Fatal("old G68 inverse accepted")
	}
}
func TestG70ActualForwardAndInversePostimage(t *testing.T) {
	root := os.Getenv("G70_PLAN_ROOT")
	if root == "" {
		t.Skip("retained private WIMs not supplied")
	}
	for _, name := range []string{"G70-wim-forward.json", "G70-wim-inverse.json"} {
		b, e := os.ReadFile(filepath.Join(root, "private", name))
		if e != nil {
			t.Fatal(e)
		}
		var p WIMPlan
		if e = json.Unmarshal(b, &p); e != nil {
			t.Fatal(e)
		}
		if e = validateWIMPlan(p); e != nil {
			t.Fatal(e)
		}
		if e = validateRAMWIMPair(p); e != nil {
			t.Fatal(e)
		}
		file := filepath.Join(root, "..", "native-clock-G68", "private", "G68-G67-resource-v1.wim")
		if name == "G70-wim-inverse.json" {
			file = filepath.Join(root, "private", "G70-GENI-consumer-v1.wim")
		}
		f, e := os.Open(file)
		if e != nil {
			t.Fatal(e)
		}
		h, e := proposedWIMHash(f, p)
		f.Close()
		if e != nil || h != p.AfterSHA {
			t.Fatalf("%s proposed full postimage: %s %v", name, h, e)
		}
	}
}
