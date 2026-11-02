# Announcement drafts

These are drafts for the maintainer to post; no social post has been sent.

## X

Windows 11 runs natively on the OnePlus Open: desktop, internal storage and touch demonstrated. Publishing the research source for others to build on. Adreno 740/WDDM and Wi-Fi remain unfinished.
https://github.com/kevinshroff/oneplus-open-windows

## Reddit title

Windows 11 ARM64 running natively on OnePlus Open — source and detailed porting handoff

## Reddit body

I’ve been working on a native Windows 11 port for the OnePlus Open (Snapdragon 8 Gen 2 / SM8550). Full Windows has reached the desktop with the inner display, internal storage and native touchscreen working. Using the desktop with touch has been the most exciting milestone so far.

I’m publishing a source research snapshot and a detailed handoff so other people can investigate and contribute:

https://github.com/kevinshroff/oneplus-open-windows

**The important limits:** GPU acceleration and reliable Wi-Fi networking are not working yet. GMU/HFI startup works, but the GPU command processor still fails at its first start boundary. Wi-Fi initializes and exchanges initial firmware messages, then stalls before dependable networking. Everyday charging/battery management, audio, Bluetooth, cameras and full suspend/fold behavior are also incomplete.

The repository includes subsystem checklists, current driver/firmware source, credits, build boundaries and an agent handoff documenting the latest experiments and failed hypotheses. It builds on Linux/OnePlus, UniXNU/NativeAdreno, Project Mu/Project-Aloha and Mesa/Topaz work, alongside device-specific implementation.

This is not an installation release: proprietary binaries, captured device data, private operator configuration and signing material are excluded. Licensing is file-specific; please read the licensing notes before reusing code. Development is currently paused. Adreno 740/WDDM, WCN7850 transport/firmware and SM8550 platform expertise would be especially helpful.
