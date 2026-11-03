# G1342 validation record

| Check | Result | Scope |
|---|---|---|
| Whole-image delta | PASS | Four changed bytes inside the approved two-DWORD table span; all other bytes identical to unsigned G1340 |
| Actual compiled REA review | PASS | New fixed table and preserved getter behavior; exported session closed |
| Native getter client | PASS | One C# compile, two PowerShell AST checks, codec pass, default inert; zero device calls |
| Init helper qualification | PASS | Existing compiled C# qualification reused because source is identical; modified policy parsed natively; no new C# compile claimed |
| Signed payload and CMS | PASS | Exact unsigned content preserved under normal PE signing changes; independent RSA/SHA256 verification using existing project identity |
| Next-flow source review | PASS | Fresh epoch/module/firmware proof, disabled GPU selection, init-only outcome and bounded loaded getter proof required |
| G1342 hardware result | Not recorded | No TX consumption or repair claim |

The init qualification explicitly reports `native_CS_compiled_in_this_action=0` and reuse of the existing G1340 native receipt. `SingleInfSelector.cs`, `Initialize-Once.ps1`, `Launch-FutureTask.ps1` and `Native-Compile-Only.ps1` are byte-identical to G1340. The changed policy binds G1342 and rejects consumed epochs. The init-only outcome remains `G1340-init-only-outcome/1`, matching the unchanged implementation.

Artifact pins:

- Unsigned: `a98840b66a8598ddb4ef2aa59300e36b4f1a6d626156b4f9aa68c1b6ec1961db`
- Signed: `c5eb06416f3f66110d7a689a059b8b240b356f4e53ea0f289e034a7f7c7adc6b`
- Actual compiled review receipt: `1e44c8ffa970e365bd572738f3e9851df0bb13276669ca0d016d780c579a13d7`
- Independent signed-content review receipt: `133313d5de7e7325a8127f0d42fab2c4e82330c24c624e262c0217257361ff16`

No OEM image, certificate, private runtime capture or signing material is included. Signature mathematics is distinct from platform trust and successful driver loading.
