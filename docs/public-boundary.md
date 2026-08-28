# Public and private boundary

## Public repository

This repository is intended to contain original Open Trestle source code, tests, public documentation, contribution materials, release metadata, and reproducible build instructions.

Public documentation describes shipped behavior in the present tense. Planned behavior is labeled as planned. Public material does not include credentials, private prompts, internal routing logic, agent transcripts, model outputs, private work instructions, copied upstream source, or non-public third-party material.

## Local references

The local `references/` directory is intentionally ignored by Git. It may contain research notes, source archives, inspected upstream material, internal planning records, and agent-specific artifacts. It is not product source, a distribution input, or a public documentation dependency.

A public file must not link to, import from, or require `references/`. If a public claim needs support, the claim must be independently documented in the public tree or reduced to the evidence available there.

## Release review

Before a public release, maintainers must verify that the tracked tree contains only public-safe material, that generated artifacts are reproducible from tracked source, and that no ignored local material is staged or referenced. A clean Git status alone is not sufficient evidence of a public-safe release.
