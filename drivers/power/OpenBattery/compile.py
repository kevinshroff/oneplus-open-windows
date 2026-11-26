#!/usr/bin/env python3
"""Offline ARM64 WDK compiler for OpenBattery.sys (Windows Battery Class Minidriver)."""
import argparse, pathlib, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", default="/Library/Developer/CommandLineTools/usr/bin/clang")
    ap.add_argument("--wdk-km", required=True)
    ap.add_argument("--sdk-shared", required=True)
    ap.add_argument("--sdk-ucrt", required=True)
    ap.add_argument("--msvc-inc", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    out = pathlib.Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    src = HERE / "open_battery.c"
    obj = out / "open_battery.obj"

    cmd = [
        args.compiler,
        "--target=aarch64-pc-windows-msvc",
        "-ffreestanding", "-fms-extensions", "-fms-compatibility",
        "-fno-stack-protector", "-O2", "-std=c11",
        "-D_ARM64_=1", "-D_KERNEL_MODE",
        "-DNTDDI_VERSION=0x0A00000C", "-D_WIN32_WINNT=0x0A00",
        "-D_NO_CRT_STDIO_INLINE",
        "-Wall", "-Wextra", "-Werror",
        "-isystem", args.wdk_km,
        "-isystem", args.sdk_shared,
        "-isystem", args.sdk_ucrt,
        "-isystem", args.msvc_inc,
        "-c", str(src), "-o", str(obj),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(f"FAILED:\n{r.stdout}\n{r.stderr}", file=sys.stderr)
        sys.exit(r.returncode)
    print(f"OK open_battery.c -> {obj} ({obj.stat().st_size} bytes)")

if __name__ == "__main__":
    main()
