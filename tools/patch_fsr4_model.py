#!/usr/bin/env python3
"""
patch_fsr4_model.py - FSR 4.1.2 (amdxcffx64.dll) model-selection override patcher.

Adds OptiScaler-style environment variables that force exactly one provider
per effect type to report itself as supported, regardless of the GPU
generation detected via DXGI:

  FSR4_MODEL   - upscaler providers
  FSR_FG_MODE  - frame-generation providers (ML frame gen vs classic FSR 3.1)

Providers and their IsSupported gates (RVAs, FSR 4.1.2 amdxcffx64.dll):

  Provider                      iface vtable  gate RVA   native GPU check
  ----------------------------  ------------  --------   --------------------------------
  FSR4 (FP8)                    0x4f6b440     0x1108e0   RDNA4 (gfx12xx)
  FSR4-i8                       0x4f6b4d8     0x112360   RDNA3 (gfx11xx)
  FSR4L-i8                      0x4f6b580     0x112b80   RDNA3.5 (family 0x96)
  FSR4-i8-2                     0x4f6b5e8     0x1135f0   RDNA2 / Navi2x (family 0x8f)
  FSR3 (3.1.6)                  0x4f6b488     0x110a10   capability flag (bit 16), any GPU

  MLFrameGeneration (4.0.2)     0x4f676b0     0x0e6e90   driver capability check
  MLFrameGenerationSwapChain    0x4f679e8     0x0eeda0   family 0x98 (RDNA4) only
  Fsr3FrameGeneration (3.1.7)   0x23e4c0*     0x0071b0   always supported (mov al,1)
  Fsr3FrameGenerationSwapChain  0x4f67950     0x0071b0   always supported (shared gate)

  (*) the Fsr3FrameGeneration vtable lives in .text (thunk region); its
      IsSupported slot points at the shared always-true gate 0x71b0.

FSR4_MODEL values (case-insensitive):
  FSR4 | FP8                   -> force the FP8 model (RDNA4 weights)
  INT8 | I8                    -> force the INT8 model (RDNA3 weights)
  INT8_LITE | LITE             -> force the INT8 lite model
  INT8_NAVI2 | NAVI2           -> force the INT8 Navi2 (RDNA2) model
  FSR3 | FSR31 | FSR3.1 | NONE -> force the classic FSR 3.1.6 upscaler
  unset / empty                -> original behaviour

FSR_FG_MODE values (case-insensitive):
  ML | MLFG | MLFG4 | FSR4      -> force the ML Frame Generation providers
  FSR3 | FSR31 | FSR3.1 | NONE -> force the classic FSR 3.1.7 frame generation
  unset / empty                -> original behaviour

The FSR_FG_MODE override is independent of Proton's MLFG_UPGRADE (which swaps
which driver DLL gets loaded); it selects the provider within this DLL.

Implementation:
  - appends a new executable PE section (.f4env) holding the override stubs
  - each gate's prologue is replaced by a 5-byte jmp into its thunk
  - the thunk reads its env var through the DLL's own getenv IAT entry
    (rva 0x21d3c8) and compares case-insensitively against the provider
    aliases: a match returns 1, a mismatch (variable set) returns 0, an unset
    or empty variable re-executes the saved prologue and jumps back into the
    original gate
  - the stub is fully rip-relative, so it is ASLR-safe without .reloc entries
"""

import argparse
import os
import struct
import sys

try:
    import pefile
except ImportError:
    sys.exit("error: pefile is required (pip install pefile)")

try:
    from keystone import Ks, KS_ARCH_X86, KS_MODE_64
except ImportError:
    sys.exit("error: keystone-engine is required (pip install keystone-engine)")

IMAGE_BASE = 0x180000000
GETENV_IAT_VA = IMAGE_BASE + 0x21D3C8
SECTION_NAME = b".f4env"

# (gate rva, label, aliases, prologue asm text, prologue bytes, resume offset)
# resume = how many prologue bytes the thunk re-executes before jumping back
UPSCALER_GATES = [
    (0x1108E0, "FP8",        ["FSR4", "FP8"],
     "push rbx\nsub rsp, 0x40",     b"\x40\x53\x48\x83\xEC\x40",         6),
    (0x112360, "INT8",       ["INT8", "I8"],
     "push rbx\nsub rsp, 0x40",     b"\x40\x53\x48\x83\xEC\x40",         6),
    (0x112B80, "INT8_LITE",  ["INT8_LITE", "LITE"],
     "sub rsp, 0x48\nmov rax, rdx", b"\x48\x83\xEC\x48\x48\x8B\xC2", 7),
    (0x1135F0, "INT8_NAVI2", ["INT8_NAVI2", "NAVI2"],
     "sub rsp, 0x48\nmov rax, rdx", b"\x48\x83\xEC\x48\x48\x8B\xC2", 7),
    (0x110A10, "FSR3",       ["FSR3", "FSR31", "FSR3.1", "NONE"],
     "and edx, 0xff0000",          b"\x81\xE2\x00\x00\xFF\x00",         6),
]

FG_GATES = [
    # ML frame generation (provider vtable 0x4f676b0, slot2)
    (0x0E6E90, "FG_ML",      ["ML", "MLFG", "MLFG4", "FSR4"],
     "push rbx\nsub rsp, 0x150",  b"\x40\x53\x48\x81\xEC\x50\x01\x00\x00", 9),
    # ML frame generation swapchain (provider vtable 0x4f679e8, slot2)
    (0x0EEDA0, "FG_ML_SC",   ["ML", "MLFG", "MLFG4", "FSR4"],
     "sub rsp, 0x48\nxor ecx, ecx", b"\x48\x83\xEC\x48\x33\xC9",           6),
    # shared always-true gate for both Fsr3 frame generation providers
    # 3 bytes: mov al,1; ret. The 5-byte jmp spans into the following int3
    # padding (never executed); the original path re-executes the whole
    # function inline, so resume is None.
    (0x0071B0, "FG_FSR3",    ["FSR3", "FSR31", "FSR3.1", "NONE"],
     "mov al, 1\nret",             b"\xB0\x01\xC3\xCC\xCC",               None),
]

ENV_GROUPS = [
    ("FSR4_MODEL",  UPSCALER_GATES),
    ("FSR_FG_MODE", FG_GATES),
]

KS = Ks(KS_ARCH_X86, KS_MODE_64)

# unique marker displacements for rip-relative fixups
MARK_ENV = 0x07ABA01
MARK_GETENV = 0x07ABA02
MARK_ALIAS_BASE = 0x07ABA10  # + index

STRCMP_CI = """
    xor eax, eax
l_loop:
    movzx r8w, byte ptr [rcx]
    movzx r9w, byte ptr [rdx]
    mov r10w, r8w
    or r10w, 0x20
    mov r11w, r9w
    or r11w, 0x20
    cmp r8w, 0x41
    jb l_s1
    cmp r8w, 0x5a
    ja l_s1
    mov r8w, r10w
l_s1:
    cmp r9w, 0x41
    jb l_s2
    cmp r9w, 0x5a
    ja l_s2
    mov r9w, r11w
l_s2:
    cmp r8w, r9w
    jne l_ne
    test r8w, r8w
    jz l_eq
    inc rcx
    inc rdx
    jmp l_loop
l_ne:
    mov eax, 1
    ret
l_eq:
    xor eax, eax
    ret
"""

POPS = ("pop rax\npop r11\npop r10\npop r9\npop r8\n"
        "pop rdx\npop rcx\npop rdi\npop rbx\n")


def asm(code, va):
    enc, _ = KS.asm(code, addr=va)
    if not enc:
        raise RuntimeError("keystone produced no code for:\n" + code)
    return bytes(enc)


def fix_markers(buf, thunk_va, fixups):
    """Replace marker disp32s in buf. fixups: {marker: target_va}."""
    out = bytearray(buf)
    for marker, target in fixups.items():
        pat = struct.pack("<i", marker)
        idx = out.find(pat)
        if idx < 0:
            raise RuntimeError("marker 0x%x not found in encoding" % marker)
        if out.find(pat, idx + 1) >= 0:
            raise RuntimeError("marker 0x%x occurs more than once" % marker)
        insn_end_va = thunk_va + idx + 4
        out[idx:idx + 4] = struct.pack("<i", target - insn_end_va)
    return bytes(out)


def build_thunk(thunk_va, gate_rva, resume, prologue_asm, alias_vas, env_va, strcmp_va):
    if resume is None:
        # gate fully re-executed inline (tiny always-true gate: mov al,1; ret
        # is only 3 bytes, so the patched jmp spans into the following int3
        # padding and there is nothing left to jump back to)
        orig_tail = prologue_asm
    else:
        orig_tail = prologue_asm + "\njmp 0x%x" % (IMAGE_BASE + gate_rva + resume)
    src = []
    src.append("push rbx\npush rdi\npush rcx\npush rdx\npush r8\npush r9\n"
               "push r10\npush r11\npush rax")
    src.append("lea rcx, qword ptr [rip + 0x%x]" % MARK_ENV)
    src.append("xor eax, eax")
    src.append("call qword ptr [rip + 0x%x]" % MARK_GETENV)
    src.append("test rax, rax\njz l_orig")
    src.append("cmp byte ptr [rax], 0\njz l_orig")
    src.append("mov rdi, rax")
    fixups = {MARK_ENV: env_va, MARK_GETENV: GETENV_IAT_VA}
    for i, av in enumerate(alias_vas):
        marker = MARK_ALIAS_BASE + i
        fixups[marker] = av
        src.append("mov rcx, rdi")
        src.append("lea rdx, qword ptr [rip + 0x%x]" % marker)
        src.append("call 0x%x" % strcmp_va)
        src.append("test eax, eax\njz l_true")
    # fallthrough: variable set but no alias matched -> force unsupported
    src.append(POPS + "xor eax, eax\nret")
    src.append("l_true:\n" + POPS + "mov eax, 1\nret")
    src.append("l_orig:\n" + POPS + orig_tail)
    code = asm("\n".join(src), thunk_va)
    return fix_markers(code, thunk_va, fixups)


def build_section(sec_rva):
    """Build the .f4env contents. Returns (bytes, {gate_rva: thunk_rva})."""
    data = bytearray()
    str_off = {}

    def put_str(s):
        if s in str_off:
            return str_off[s]
        off = len(data)
        data.extend(s.encode() + b"\x00")
        str_off[s] = off
        return off

    env_off = {name: put_str(name) for name, _ in ENV_GROUPS}
    alias_off = {}
    for _, gates in ENV_GROUPS:
        for _, _, aliases, _, _, _ in gates:
            for a in aliases:
                alias_off[a] = put_str(a)
    while len(data) % 16:
        data.append(0)

    def va(off):
        return IMAGE_BASE + sec_rva + off

    code = bytearray()
    strcmp_rva_off = len(data)
    code += asm(STRCMP_CI, va(strcmp_rva_off))
    thunks = {}
    for env_name, gates in ENV_GROUPS:
        e_off = env_off[env_name]
        for gate_rva, label, aliases, pro_asm, _, resume in gates:
            t_off = len(data) + len(code)
            t_va = va(t_off)
            thunks[gate_rva] = sec_rva + t_off
            code += build_thunk(t_va, gate_rva, resume, pro_asm,
                                [va(alias_off[a]) for a in aliases],
                                va(e_off), va(strcmp_rva_off))
    return bytes(data) + bytes(code), thunks


def align(x, a):
    return (x + a - 1) & ~(a - 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("input", help="original FSR 4.1.2 amdxcffx64.dll")
    ap.add_argument("output", help="patched dll path")
    ap.add_argument("--keep-prologue-bytes", action="store_true",
                    help="do not overwrite the remaining gate prologue bytes with 0xCC")
    args = ap.parse_args()

    pe = pefile.PE(args.input)

    sec_align = pe.OPTIONAL_HEADER.SectionAlignment
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    nsec = pe.FILE_HEADER.NumberOfSections
    sec_table = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    first_raw = min(s.PointerToRawData for s in pe.sections)
    if sec_table + (nsec + 1) * 40 > first_raw:
        sys.exit("error: no room in headers for an extra section")

    sec_rva = align(pe.OPTIONAL_HEADER.SizeOfImage, sec_align)
    blob, thunks = build_section(sec_rva)
    vsize = len(blob)
    raw_size = align(vsize, file_align)
    raw_ptr = align(os.path.getsize(args.input), file_align)

    for _, gates in ENV_GROUPS:
        for gate_rva, label, _, _, pro_bytes, _ in gates:
            actual = pe.get_data(gate_rva, len(pro_bytes))
            if actual != pro_bytes:
                sys.exit("error: gate %s at rva 0x%X has unexpected bytes %s "
                         "(expected %s) - not FSR 4.1.2?"
                         % (label, gate_rva, actual.hex(), pro_bytes.hex()))

    data = bytearray(pe.__data__)
    # extend file
    if len(data) > raw_ptr:
        sys.exit("error: file larger than expected alignment slot")
    data.extend(b"\x00" * (raw_ptr - len(data)))
    data.extend(blob)
    data.extend(b"\x00" * (raw_size - vsize))

    # section header
    name_off = sec_table + nsec * 40
    hdr = bytearray(40)
    hdr[0:8] = SECTION_NAME.ljust(8, b"\x00")
    struct.pack_into("<IIII", hdr, 8, vsize, sec_rva, raw_size, raw_ptr)
    struct.pack_into("<I", hdr, 36, 0x60000020)  # characteristics: code|executed|read
    data[name_off:name_off + 40] = hdr

    # optional header updates
    opt_off = pe.DOS_HEADER.e_lfanew + 24
    struct.pack_into("<H", data, pe.DOS_HEADER.e_lfanew + 6, nsec + 1)  # NumberOfSections
    struct.pack_into("<I", data, opt_off + 56, align(sec_rva + vsize, sec_align))  # SizeOfImage

    # patch gates: jmp rel32 (+ optional int3 padding)
    for _, gates in ENV_GROUPS:
        for gate_rva, label, _, _, pro_bytes, _ in gates:
            t_rva = thunks[gate_rva]
            rel = (IMAGE_BASE + t_rva) - (IMAGE_BASE + gate_rva + 5)
            patch = bytearray(b"\xE9" + struct.pack("<i", rel))
            pad = len(pro_bytes) - 5
            if pad > 0:
                patch += b"\xCC" * pad if not args.keep_prologue_bytes \
                    else pro_bytes[5:5 + pad]
            data[pe.get_offset_from_rva(gate_rva):pe.get_offset_from_rva(gate_rva) + len(patch)] = patch
            print("patched %-11s gate rva 0x%-7X -> thunk rva 0x%X (VA 0x%X)"
                  % (label, gate_rva, t_rva, IMAGE_BASE + t_rva))

    with open(args.output, "wb") as f:
        f.write(data)

    # fix checksum
    pe2 = pefile.PE(args.output)
    pe2.OPTIONAL_HEADER.CheckSum = pe2.generate_checksum()
    with open(args.output, "r+b") as f:
        f.seek(opt_off + 64)
        f.write(struct.pack("<I", pe2.OPTIONAL_HEADER.CheckSum))

    print("section %s: rva 0x%X vsize 0x%X raw 0x%X/0x%X"
          % (SECTION_NAME.decode(), sec_rva, vsize, raw_ptr, raw_size))
    print("wrote %s (%d bytes)" % (args.output, len(data)))
    print("usage: set FSR4_MODEL=FP8|INT8|INT8_LITE|INT8_NAVI2|FSR3|NONE")
    print("       set FSR_FG_MODE=ML|FSR3 to force a frame-generation provider")


if __name__ == "__main__":
    main()
