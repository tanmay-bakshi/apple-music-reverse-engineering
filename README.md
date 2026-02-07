# Reverse Engineering Apple Music APIs (macOS)

This repository is a lab notebook plus lightweight tooling for reverse engineering Apple Music APIs by statically analyzing the macOS Music app binary and related system frameworks.

Project rules of engagement:

- Use static analysis only (no intercepting network traffic).
- Update `HISTORY.md` frequently with hypotheses, experiments, and evidence.
- Do not commit system binaries (or huge derived artifacts). Put any large output under `out/` (gitignored) and summarize the key findings in `HISTORY.md`.

