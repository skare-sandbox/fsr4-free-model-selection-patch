#!/usr/bin/env python3
"""
patch_fsr4_model.py - FSR 4.1.2 (amdxcffx64.dll) model-selection override patcher.

Adds an OptiScaler-style environment variable (FSR4_MODEL) that forces exactly
one FSR4 provider to report itself as supported, regardless of the GPU
generation detected via DXGI.

Providers and their IsSupported gates (RVAs, FSR 4.1.2 amdxcffx64.dll):

  Provider      iface vtable  gate RVA   native GPU check
  ------------  ------------  --------   --------------------------------
  FSR4 (FP8)    0x4f6b450     0x1108e0   RDNA4 (gfx12xx)
  FSR4-i8       0x4f6b4e8     0x112360   RDNA3 (gfx11xx)
  FSR4L-i8      0x4f6b588     0x112b80   RDNA3.5 (family 0x96)
  FSR4-i8-2     0x4f6b5f8     0x1135f0   RDNA2 / Navi2x (family 0x8f)

FSR4_MODEL values (case-insensitive):
  FSR4 | FP8          -> force the FP8 model (RDNA4 weights)
  INT8 | I8           -> force the INT8 model (RDNA3 weights)
  INT8_LITE | LITE    -> force the INT8 lite model
  INT8_NAVI2 | NAVI2  -> force the INT8 Navi2 (RDNA2) model
  unset / empty       -> original behaviour

Implementation:
  - appends a new executable PE section (.f4env) holding the override stub
  - each gate's prologue is replaced by a 5-byte jmp into its thunk
  - the thunk reads FSR4_MODEL through the DLL's own getenv IAT entry
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
ENV_NAME = "FSR4_MODEL"
SECTION_NAME = b".f4env"

# (gate rva, label, aliases, prologue asm text, prologue bytes, resume offset)
GATES = [
    (0x1108E0, "FP8",        ["FSR4", "FP8"],
     "push rbx\nsub rsp, 0x40",     b"\x40\x53\x48\x83\xEC\x40",         6),
    (0x112360, "INT8",       ["INT8", "I8"],
     "push rbx\nsub rsp, 0x40",     b"\x40\x53\x48\x83\xEC\x40",         6),
    (0x112B80, "INT8_LITE",  ["INT8_LITE", "LITE"],
     "sub rsp, 0x48\nmov rax, rdx", b"\x48\x83\xEC\x48\x48\x8B\xC2", 7),
    (0x1135F0, "INT8_NAVI2", ["INT8_NAVI2", "NAVI2"],
     "sub rsp, 0x48\nmov rax, rdx", b"\x48\x83\xEC\x48\x48\x8B\xC2", 7),
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
    src.append("l_orig:\n" + POPS + prologue_asm)
    src.append("jmp 0x%x" % (IMAGE_BASE + gate_rva + resume))
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

    env_off = put_str(ENV_NAME)
    alias_off = {}
    for _, _, aliases, _, _, _ in GATES:
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
    for gate_rva, label, aliases, pro_asm, _, resume in GATES:
        t_off = len(data) + len(code)
        t_va = va(t_off)
        thunks[gate_rva] = sec_rva + t_off
        code += build_thunk(t_va, gate_rva, resume, pro_asm,
                            [va(alias_off[a]) for a in aliases],
                            va(env_off), va(strcmp_rva_off))
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

    for gate_rva, label, _, _, pro_bytes, _ in GATES:
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
    for gate_rva, label, _, _, pro_bytes, _ in GATES:
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
    print("usage: set %s=FP8|INT8|INT8_LITE|INT8_NAVI2 to force a model" % ENV_NAME)


if __name__ == "__main__":
    main()
