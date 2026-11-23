#!/usr/bin/env python3
"""Offline ARM64 WDK compiler for OpenChargerKeeper.
Writes all COFF objects and native-link.rsp outside the public repo (--out).
"""
import argparse, hashlib, json, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
SRC = HERE / "source"
UNITS = ["driver.c", "glink_core.c", "keeper_policy.c", "charger_codec.c", "g102_core.c", "g104_core.c"]

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", default="/Library/Developer/CommandLineTools/usr/bin/clang")
    ap.add_argument("--wdk-km", required=True)
    ap.add_argument("--wdk-kmdf", required=True)
    ap.add_argument("--sdk-shared", required=True)
    ap.add_argument("--sdk-ucrt", required=True)
    ap.add_argument("--msvc-inc", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = pathlib.Path(args.out).resolve()
    if str(out).startswith(str(HERE.parents[2])):
        raise SystemExit("Refusing to write build outputs inside the public repo")
    out.mkdir(parents=True, exist_ok=True)

    base = [
        args.compiler,
        "--target=aarch64-pc-windows-msvc",
        "-ffreestanding", "-fms-extensions", "-fms-compatibility",
        "-fno-stack-protector", "-O2", "-std=c11",
        "-D_ARM64_=1", "-D_KERNEL_MODE",
        "-DNTDDI_VERSION=0x0A00000C", "-D_WIN32_WINNT=0x0A00",
        "-D_NO_CRT_STDIO_INLINE",
        "-Wall", "-Wextra", "-Werror",
        "-isystem", args.wdk_km,
        "-isystem", args.wdk_kmdf,
        "-isystem", args.sdk_shared,
        "-isystem", args.sdk_ucrt,
        "-isystem", args.msvc_inc,
        f"-I{SRC}",
    ]

    receipt = {"units": {}}
    objs = []
    for u in UNITS:
        src = SRC / u
        obj = out / (src.stem + ".obj")
        cmd = base + ["-c", str(src), "-o", str(obj)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAILED {u}:\n{r.stdout}\n{r.stderr}", file=sys.stderr)
            sys.exit(r.returncode)
        receipt["units"][u] = {"src_sha256": sha(src), "obj_sha256": sha(obj), "obj_bytes": obj.stat().st_size}
        objs.append(obj.name)
        print(f"OK {u:20s} -> {obj.name} ({obj.stat().st_size} bytes)")

    rsp = [
        "/machine:arm64", "/driver:wdm", "/subsystem:native",
        "/entry:FxDriverEntry", "/nodefaultlib", "/incremental:no",
        "/out:OpenChargerKeeper.sys",
    ] + objs + [
        "ntoskrnl.lib", "hal.lib", "WdfLdr.lib", "WdfDriverEntry.lib",
        "libcntpr.lib", "BufferOverflowFastFailK.lib",
    ]
    (out / "native-link.rsp").write_text("\n".join(rsp) + "\n")
    (out / "COMPILE-RECEIPT.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Wrote {out / 'native-link.rsp'} and COMPILE-RECEIPT.json")

if __name__ == "__main__":
    main()
