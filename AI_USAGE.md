# AI usage disclosure

This project is open about the use of AI tools.

## Per-file attribution

### AI-generated

Everything in this repository (code, reverse engineering, documentation
drafts) was produced with AI assistance through **GLM-5.3** (model id
`zai-glm-5-3`) running in **Mistral Vibe** (agent/service).

| File | Status | Details |
|------|--------|---------|
| `tools/patch_fsr4_model.py` | AI-generated | Full patcher implementation: `.f4env` section builder, thunk generator, gate prologue patching. Based on gate RVAs and byte signatures located by AI-driven static analysis (RTTI/vtable walks, capstone disassembly) of the FSR 4.1.2 `amdxcffx64.dll`. |
| `tools/verify_patch.py` | AI-generated | Unicorn-based gate emulator and test-case matrix (98 cases), including the mock `getenv`, call-free-gate handling and cross-variable independence checks. |
| Reverse-engineering findings (gate RVAs, provider tables, RTTI mapping) | AI-generated | All provider `IsSupported` gates (upscaler + frame generation) were located and disassembled with AI assistance; the raw analysis was performed against the official Adrenalin 26.10.1 driver DLL fetched in a sandbox (never committed). |

### AI-suggested, human-edited

| File | Status | Details |
|------|--------|---------|
| `README.md` | AI-suggested, human-edited | Structure and technical sections drafted by AI; wording, emphasis, publication decisions and the "delivered by our humble AI overlords" framing reviewed and adjusted by the human owner. Post-merge title/content tweaks (`af18370`, `8472ed9`, `9eb8e9b`) are fully human. |

### Fully hand-written

| File | Status | Details |
|------|--------|---------|
| Post-merge README adjustments (`33e90c7` and the branch follow-ups above) | Human | Owner-authored edits. |

## Per-commit attribution

The following commits on `main` were AI-generated via **GLM-5.3
(`zai-glm-5-3`) + Mistral Vibe**:

- `f41e884` Add FSR3 (3.1.6) provider to FSR4_MODEL override
- `c150a70` Add NONE alias for FSR3 and document the full provider inventory
- `a1f2ba1` Add FSR_FG_MODE frame-generation provider override (ML vs FSR3)

These commits were merged into `main` (PR #2, merge `80f79ca`) before the
`Assisted-by:` trailer convention was adopted, so their messages cannot be
amended retroactively without rewriting published history; this file serves
as the authoritative attribution record for them. All subsequent AI-authored
commits carry the trailer:

```
Assisted-by: GLM-5.3 (zai-glm-5-3) via Mistral Vibe
```
