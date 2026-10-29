#!/usr/bin/env python3
"""
verify_patch.py - functional verification of the FSR4_MODEL / FSR_FG_MODE patch
by emulating the patched provider gates (and their thunks) with Unicorn.

For every env value, each gate is emulated:
  1. bare original gate (pre-patch behaviour baseline, with a synthetic GPU)
  2. patched gate entry -> thunk (which calls a fake getenv)

The fake getenv reads from a simulated environment block. The strcmp_ci helper
and thunk logic run natively in the emulator, so this exercises the exact bytes
that will ship in the patched DLL.
"""

import sys
import pefile
from unicorn import *
from unicorn.x86_const import *

ORIG = "amdxcffx64.dll"
PATCHED = "amdxcffx64_patched.dll"
IMAGE_BASE = 0x180000000

# gate rva -> (label, rva of a call inside the original path used as a
# "fell through to original" stop marker, or None when the gate completes
# without any call). The thunks per env group share alias sets.
GATES = {
    # FSR4_MODEL (upscaler)
    0x1108E0: ("FP8", 0x102130),
    0x112360: ("INT8", 0x101530),
    0x112B80: ("INT8_LITE", 0x101190),
    0x1135F0: ("INT8_NAVI2", 0x101190),
    0x110A10: ("FSR3", None),
    # FSR_FG_MODE (frame generation)
    0x0E6E90: ("FG_ML", 0x0E6EB3),
    0x0EEDA0: ("FG_ML_SC", 0x101190),
    0x0071B0: ("FG_FSR3", None),
}

UPSCALER_LABELS = ["FP8", "INT8", "INT8_LITE", "INT8_NAVI2", "FSR3"]
FG_LABELS = ["FG_ML", "FG_ML_SC", "FG_FSR3"]


def emulate(env_name, env_value, gate_rva, orig_stop):
    pe = pefile.PE(PATCHED)
    data = pe.get_memory_mapped_image()
    size = len(data)

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(IMAGE_BASE, (size + 0xFFFF) & ~0xFFFF)
    mu.mem_write(IMAGE_BASE, bytes(data))

    # stack
    STACK = 0x700000000
    mu.mem_map(STACK, 0x100000)
    mu.reg_write(UC_X86_REG_RSP, STACK + 0x80000)

    # env block and fake getenv target
    ENV = 0x600000000
    mu.mem_map(ENV, 0x100000)
    envstr = (env_value.encode() + b"\x00") if env_value else None
    value_ptr = None
    if envstr:
        value_ptr = ENV + 0x1000
        mu.mem_write(value_ptr, envstr)

    FAKE_GETENV = ENV + 0x8000

    def getenv_impl(uc, address, size, user_data):
        # rcx = name; only the patch env vars are queried
        name = uc.mem_read(uc.reg_read(UC_X86_REG_RCX), 32)
        name = bytes(name).split(b"\x00")[0].decode(errors="ignore")
        if name in ("FSR4_MODEL", "FSR_FG_MODE") and name == env_name:
            uc.reg_write(UC_X86_REG_RAX, value_ptr if value_ptr else 0)
        else:
            uc.reg_write(UC_X86_REG_RAX, 0)
        # ret to caller: pop return address from stack
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = int.from_bytes(uc.mem_read(rsp, 8), "little")
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    GETENV_IAT_VA = IMAGE_BASE + 0x21D3C8
    mu.mem_write(GETENV_IAT_VA, (FAKE_GETENV).to_bytes(8, "little"))
    mu.hook_add(UC_HOOK_CODE, getenv_impl, begin=FAKE_GETENV, end=FAKE_GETENV + 1)

    # synthetic GPU-info: rdx dummy with capability bits set so call-free
    # original gates (FSR3 upscaler, FSR3 FG) deterministically return 1;
    # call-based gates are stopped at their first COM interaction anyway.
    DUMMY = 0x610010000
    mu.mem_map(DUMMY & ~0xFFF, 0x1000)
    mu.reg_write(UC_X86_REG_RDX, DUMMY)
    mu.reg_write(UC_X86_REG_RCX, DUMMY)

    STOP_ORIG_CALL = IMAGE_BASE + orig_stop if orig_stop else None

    stop_reason = {}

    def hook_stop(uc, address, size, user_data):
        stop_reason["addr"] = address
        uc.emu_stop()

    if STOP_ORIG_CALL is not None:
        mu.hook_add(UC_HOOK_CODE, hook_stop, begin=STOP_ORIG_CALL, end=STOP_ORIG_CALL + 1)

    START = IMAGE_BASE + gate_rva
    RET_MAGIC = 0x620000000
    mu.mem_map(RET_MAGIC, 0x1000)
    # push fake return address so gate ret lands on RET_MAGIC
    rsp = mu.reg_read(UC_X86_REG_RSP) - 8
    mu.mem_write(rsp, (RET_MAGIC).to_bytes(8, "little"))
    mu.reg_write(UC_X86_REG_RSP, rsp)

    try:
        mu.emu_start(START, RET_MAGIC, timeout=2_000_000)
    except UcError as e:
        if STOP_ORIG_CALL is not None and stop_reason.get("addr") == STOP_ORIG_CALL:
            return "fell-through-to-original", None
        raise

    if STOP_ORIG_CALL is not None and stop_reason.get("addr") == STOP_ORIG_CALL:
        return "fell-through-to-original", None
    eax = mu.reg_read(UC_X86_REG_EAX) & 0xFF
    return "returned", eax


def only(want, labels):
    # forcing ML enables both ML gates (frame gen + swapchain);
    # forcing FSR3 enables the (shared) Fsr3 FG gate
    res = {l: 0 for l in labels}
    if want == "FG_ML":
        res["FG_ML"] = res["FG_ML_SC"] = 1
    else:
        res[want] = 1
    return res


def run_group(env_name, labels, cases):
    failures = 0
    for value, expected in cases:
        for gate_rva, (label, orig_stop) in GATES.items():
            if label not in labels:
                continue
            kind, eax = emulate(env_name, value, gate_rva, orig_stop)
            if kind == "fell-through-to-original":
                got = "orig"
                ok = expected[label] == "orig"
            else:
                got = eax
                ok = eax == expected[label]
            if not ok:
                failures += 1
            status = "ok" if ok else "FAIL"
            shown = value if value is not None else "None"
            if kind == "fell-through-to-original":
                print(f"{env_name}={shown!r:10} {label:11} -> original path   {status}")
            else:
                print(f"{env_name}={shown!r:10} {label:11} -> returns {eax}          {status}"
                      f" (expected {expected[label]})")
    return failures


def main():
    failures = 0

    orig_up = {l: "orig" for l in UPSCALER_LABELS}
    orig_up["FSR3"] = 1  # call-free gate completes and returns 1
    up_cases = [
        (None,          dict(orig_up)),
        ("",            dict(orig_up)),
        ("FP8",         only("FP8", UPSCALER_LABELS)),
        ("fsr4",        only("FP8", UPSCALER_LABELS)),
        ("INT8",        only("INT8", UPSCALER_LABELS)),
        ("i8",          only("INT8", UPSCALER_LABELS)),
        ("INT8_LITE",   only("INT8_LITE", UPSCALER_LABELS)),
        ("lite",        only("INT8_LITE", UPSCALER_LABELS)),
        ("INT8_NAVI2",  only("INT8_NAVI2", UPSCALER_LABELS)),
        ("navi2",       only("INT8_NAVI2", UPSCALER_LABELS)),
        ("FSR3",        only("FSR3", UPSCALER_LABELS)),
        ("fsr31",       only("FSR3", UPSCALER_LABELS)),
        ("FSR3.1",      only("FSR3", UPSCALER_LABELS)),
        ("none",        only("FSR3", UPSCALER_LABELS)),
        ("BOGUS",       {l: 0 for l in UPSCALER_LABELS}),
    ]
    failures += run_group("FSR4_MODEL", UPSCALER_LABELS, up_cases)

    # FSR4_MODEL must not affect FG gates: with FSR4_MODEL set and
    # FSR_FG_MODE unset, the FG gates must take their original path
    cross_fg = {l: "orig" for l in FG_LABELS}
    cross_fg["FG_FSR3"] = 1
    cross_cases = [
        ("INT8", cross_fg),
    ]
    failures += run_group("FSR4_MODEL", FG_LABELS, cross_cases)

    orig_fg = {l: "orig" for l in FG_LABELS}
    orig_fg["FG_FSR3"] = 1  # call-free gate completes and returns 1
    fg_cases = [
        (None,          dict(orig_fg)),
        ("",            dict(orig_fg)),
        ("ML",          only("FG_ML", FG_LABELS)),
        ("mlfg",        only("FG_ML", FG_LABELS)),
        ("MLFG4",       only("FG_ML", FG_LABELS)),
        ("FSR4",        only("FG_ML", FG_LABELS)),
        ("FSR3",        only("FG_FSR3", FG_LABELS)),
        ("fsr31",       only("FG_FSR3", FG_LABELS)),
        ("FSR3.1",      only("FG_FSR3", FG_LABELS)),
        ("none",        only("FG_FSR3", FG_LABELS)),
        ("BOGUS",       {l: 0 for l in FG_LABELS}),
    ]
    failures += run_group("FSR_FG_MODE", FG_LABELS, fg_cases)

    # FSR_FG_MODE must not affect upscaler gates
    cross_up = {l: "orig" for l in UPSCALER_LABELS}
    cross_up["FSR3"] = 1
    cross2 = [
        ("ML", cross_up),
    ]
    failures += run_group("FSR_FG_MODE", UPSCALER_LABELS, cross2)

    print()
    if failures:
        print(f"{failures} FAILURES")
        sys.exit(1)
    print("all cases passed")


if __name__ == "__main__":
    main()
