# fsr4-reverse-engineering-efforts

Reverse engineering of AMD's FSR 4.1.2 `amdxcffx64.dll` (the `ffx_api` backend
provider DLL) with the goal of full, external control over the FSR4 model
selection — in the spirit of [OptiScaler](https://github.com/OptiScaler/OptiScaler).

## TL;DR

`tools/patch_fsr4_model.py` patches the DLL so that the environment variable
`FSR4_MODEL` forces a specific FSR4 provider/model regardless of the detected
GPU generation:

```
FSR4_MODEL=FP8          # FSR4 (FP8 weights, RDNA4 path)
FSR4_MODEL=INT8         # FSR4-i8 (INT8 weights, RDNA3 path)
FSR4_MODEL=INT8_LITE    # FSR4L-i8 (INT8 lite weights)
FSR4_MODEL=INT8_NAVI2    # FSR4-i8-2 / Navi2 (INT8, RDNA2 path)
```

Unset or unrecognized values leave the DLL's original behaviour fully intact.

```
pip install pefile keystone-engine
python3 tools/patch_fsr4_model.py amdxcffx64.dll amdxcffx64_patched.dll
python3 tools/verify_patch.py     # optional: emulate & verify all gates
```

## Reverse-engineered model selection (FSR 4.1.2)

The DLL registers four FSR4 providers with the `ffx_api` dispatcher
(`UpdateFfxApiProvider`/`UpdateFfxApiProviderEx` at rva `0x219AB0`/`0x219AF0`):

| Provider       | name string | iface vtable | `IsSupported` gate | native check                    |
|----------------|-------------|--------------|--------------------|---------------------------------|
| `ffxProvider_FSR4`          | `FSR4`      | rva `0x4f6b450` | `0x1108e0` | RDNA4 (gfx12xx)                 |
| `ffxProvider_FSR4_Int8`    | `FSR4-i8`   | rva `0x4f6b4e8` | `0x112360` | RDNA3 (gfx11xx)                 |
| `ffxProvider_FSR4Lite_Int8`| `FSR4L-i8`  | rva `0x4f6b588` | `0x112b80` | RDNA3.5 (family 0x96)           |
| `ffxProvider_FSR4_Int8_Navi2` | `FSR4-i8-2` | rva `0x4f6b5f8` | `0x1135f0` | RDNA2 / Navi2x (family 0x8f)  |

Each gate parses the adapter description (helper at `0x101190`, fed by DXGI)
into a small struct, then compares:

- `0x112360` (RDNA3): family `0x91`, device ranges `1..0xF`, `0x10..0x1F`, `0x20..0xFE`, or family `0x96` devices `0xC0..0xCF`, `0xC8`
- `0x112b80` (RDNA3.5): family `0x96`, devices `1..0x3F` or `0x1A`
- `0x1135f0` (RDNA2): family `0x8f`, devices `0x28..0x4F`
- `0x1108e0` (RDNA4): driver feature check (`0x102130`) plus family check

The provider that reports support wins; the actual upscaler model class
(`Fsr4UpscalerModel`, `Fsr4Int8UpscalerModel`, `Fsr4Int8navi2UpscalerModel`,
`Fsr4LiteInt8UpscalerModel` — all visible via RTTI) is then created through the
`CreateModel(internal_context, correctPreset, model)` path (assert string at
rva `0x4f6ca90`, call site `0x122d4d`). The "preset" quality selection
(`[ctx+0x208]`, computed at `0x120647`..`0x1206f3`) is orthogonal to the
provider/model choice.

AMD already reads environment variables for other toggles (`MLSR-WATERMARK`,
`MLFI-WATERMARK` at `0x120745`/`0xe9f92`), but there is no built-in model
override — hence this patch.

## How the patch works

1. Appends a new executable section `.f4env` (rva `0x504A000`) containing:
   - the `FSR4_MODEL` name + provider alias strings
   - a case-insensitive `strcmp` helper
   - one thunk per provider gate
2. Replaces each gate's prologue with a `jmp` into its thunk (5 bytes, pad with
   `int3`).
3. The thunk:
   - saves all volatile registers, calls `getenv("FSR4_MODEL")` through the
     DLL's own IAT slot (rva `0x21d3c8` — no new imports needed)
   - unset/empty → restores registers, re-executes the saved prologue bytes
     and jumps back into the original gate (bit-for-bit original behaviour)
   - value matches this provider's aliases → returns 1 (supported)
   - value set but matches another provider → returns 0 (unsupported), so
     exactly one provider reports support and the ffx_api dispatcher picks it
4. Everything is RIP-relative — no absolute addresses, no new `.reloc` entries,
   ASLR-safe.

`tools/verify_patch.py` emulates each patched gate with Unicorn (including a
mock `getenv`) and asserts the expected outcome for unset/empty/each alias and
unknown values — all 44 cases pass.

## Status / caveats

- Verified statically and via emulation; **not yet tested on real hardware**.
- Forcing a model whose weights target a different GPU generation (e.g. FP8 on
  RDNA3) may fail at shader compilation or produce visual artifacts — the
  provider gates exist for a reason. The patch gives you the choice; it cannot
  add hardware capabilities.
- Gate offsets are specific to FSR 4.1.2 (`amdxcffx64.dll`, timestamp
  `0x6ac90bb5`); the patcher validates the expected prologue bytes and refuses
  to patch anything else.
- Related: [fsr4-lite-on-rdna3-patches](https://github.com/skare-sandbox/fsr4-lite-on-rdna3-patches)
  (previous GPU-spoofing approach).
