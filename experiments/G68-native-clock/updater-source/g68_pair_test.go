package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestG68RejectsPreviousQualifiedG65Pair(t *testing.T) {
	p := WIMPlan{Version: "G21-trial-wim-v1", Name: trialWIMName,
		BeforeBytes: 592882167, AfterBytes: 594423099,
		BeforeSHA: "bf8da75a5ff96af9c65fb5f059e6cbb8206595aeeee9c5057e31e31bd4e30250",
		AfterSHA:  "cbde3b27ab321d054d463e6ebf1c803dea6bb00b3b09419b9c6b8afdeda6aed7"}
	if validateRAMWIMPair(p) == nil {
		t.Fatal("old G65 pair accepted")
	}
	p.BeforeBytes, p.AfterBytes = p.AfterBytes, p.BeforeBytes
	p.BeforeSHA, p.AfterSHA = p.AfterSHA, p.BeforeSHA
	if validateRAMWIMPair(p) == nil {
		t.Fatal("old G65 inverse accepted")
	}
}
func TestG68ActualForwardAndInversePostimage(t *testing.T) {
	root := os.Getenv("G68_PLAN_ROOT")
	if root == "" {
		t.Skip("retained private WIMs not supplied")
	}
	for _, name := range []string{"G68-wim-forward.json", "G68-wim-inverse.json"} {
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
		file := filepath.Join(root, "..", "ram-handoff-G64", "private", "G64-G63-resource-v1.wim")
		if name == "G68-wim-inverse.json" {
			file = filepath.Join(root, "private", "G68-G67-resource-v1.wim")
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
