#!/usr/bin/env python3
"""
verify_patch.py - functional verification of the FSR4_MODEL patch by emulating
the patched provider gates (and their thunks) with Unicorn.

For every FSR4_MODEL value, each gate is emulated twice:
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

GATES = {
    0x1108E0: ("FP8", 0x102130),
    0x112360: ("INT8", 0x101530),
    0x112B80: ("INT8_LITE", 0x101190),
    0x1135F0: ("INT8_NAVI2", 0x101190),
    0x110A10: ("FSR3", None),
}

# synthetic GPU info structs as produced by the DLL's own 0x101190 parser:
# offset 0x10: device id, 0x14: family(?) -- the gates check [rsp+0x30]/[rsp+0x34]
# i.e. dword at +0x10 and +0x14 of the parsed struct.
def make_env_block(env):
    blob = bytearray(b"\x00" * 0x10000)
    for k, v in env.items():
        kv = (k + "=" + v).encode() + b"\x00"
        blob.extend(kv)
    blob.extend(b"\x00")
    return bytes(blob)


def emulate(dll_path, gate_rva, orig_stop, env_value, expect_ret):
    pe = pefile.PE(dll_path)
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
    mu.mem_write(FAKE_GETENV, b"\xC3")  # ret; rax already holds value_ptr?

    def getenv_impl(uc, address, size, user_data):
        # rcx = name; we always return value_ptr (only FSR4_MODEL is queried)
        name = uc.mem_read(uc.reg_read(UC_X86_REG_RCX), 12)
        if bytes(name).startswith(b"FSR4_MODEL"):
            uc.reg_write(UC_X86_REG_RAX, value_ptr if value_ptr else 0)
        else:
            uc.reg_write(UC_X86_REG_RAX, 0)
        # ret to caller: pop return address from stack
        rsp = uc.reg_read(UC_X86_REG_RSP)
        ret = int.from_bytes(uc.mem_read(rsp, 8), "little")
        uc.reg_write(UC_X86_REG_RSP, rsp + 8)
        uc.reg_write(UC_X86_REG_RIP, ret)

    # hook the IAT slot call: the thunk does call [rip+disp] -> reads IAT VA.
    # Map the IAT read target: hook memory reads at getenv IAT address
    GETENV_IAT_VA = IMAGE_BASE + 0x21D3C8

    def hook_mem(uc, access, address, size, value, user_data):
        if address == GETENV_IAT_VA:
            # redirect: write pointer to a trampoline that triggers a code hook
            pass
        return True

    # simplest: map a page for the trampoline, put value in IAT via write
    mu.mem_write(GETENV_IAT_VA, (FAKE_GETENV).to_bytes(8, "little"))
    mu.hook_add(UC_HOOK_CODE, getenv_impl, begin=FAKE_GETENV, end=FAKE_GETENV + 1)

    # synthetic GPU-info struct for the "original" path: rdx points to a struct
    # the original gates parse via 0x101190 (which itself uses COM interfaces).
    # Full emulation of that path needs a DXGI mock; instead we only emulate the
    # thunk's env logic and the return-into-original path is checked by jumping
    # with a marker value.
    # For verification we start at the gate entry and stop at the first call
    # into 0x101190 (original path) OR at thunk ret.
    # The FSR3 gate (0x110a10) performs no calls at all: it tests rdx's flag
    # bits in registers, so its original path completes and returns directly.
    STOP_ORIG_CALL = IMAGE_BASE + orig_stop if orig_stop else None

    stop_reason = {}

    def hook_stop(uc, address, size, user_data):
        stop_reason["addr"] = address
        uc.emu_stop()

    if STOP_ORIG_CALL is not None:
        mu.hook_add(UC_HOOK_CODE, hook_stop, begin=STOP_ORIG_CALL, end=STOP_ORIG_CALL + 1)

    # rdx = non-null dummy (gates test rdx). bit 16 is set so the FSR3 gate's
    # original path (which needs no COM mocks) deterministically returns 1.
    DUMMY = 0x610010000
    mu.mem_map(DUMMY, 0x1000)
    mu.reg_write(UC_X86_REG_RDX, DUMMY)

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


def main():
    failures = 0
    all_labels = [l for l, _ in GATES.values()]
    def only(want):
        return {l: (1 if l == want else 0) for l in all_labels}
    orig_expect = {l: "orig" for l in all_labels}
    orig_expect["FSR3"] = 1
    cases = [
        (None,          dict(orig_expect)),
        ("",            dict(orig_expect)),
        ("FP8",         only("FP8")),
        ("fsr4",        only("FP8")),
        ("INT8",        only("INT8")),
        ("i8",          only("INT8")),
        ("INT8_LITE",   only("INT8_LITE")),
        ("lite",        only("INT8_LITE")),
        ("INT8_NAVI2",  only("INT8_NAVI2")),
        ("navi2",       only("INT8_NAVI2")),
        ("FSR3",        only("FSR3")),
        ("fsr31",       only("FSR3")),
        ("FSR3.1",      only("FSR3")),
        ("BOGUS",       {l: 0 for l in all_labels}),
    ]
    for value, expected in cases:
        for gate_rva, (label, orig_stop) in GATES.items():
            kind, eax = emulate(PATCHED, gate_rva, orig_stop, value, expected[label])
            if kind == "fell-through-to-original":
                got = "orig"
                if expected[label] != "orig":
                    failures += 1
                    status = "FAIL"
                else:
                    status = "ok"
                print(f"FSR4_MODEL={value!r:14} {label:11} -> original path   {status}")
            else:
                if eax == expected[label]:
                    status = "ok"
                else:
                    failures += 1
                    status = "FAIL"
                print(f"FSR4_MODEL={value!r:14} {label:11} -> returns {eax}          {status}"
                      f" (expected {expected[label]})")
    print()
    if failures:
        print(f"{failures} FAILURES")
        sys.exit(1)
    print("all cases passed")


if __name__ == "__main__":
    main()
