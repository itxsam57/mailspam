# Universal Email Shield Repair Program — Implementation Plan Index

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Every production behavior change follows superpowers:systematic-debugging and superpowers:test-driven-development.

**Goal:** Close every confirmed Email Shield defect in EMA-33 without weakening existing security, privacy, provider correctness, or already-working consumer workflows.

**Architecture:** Provider adapters acquire/normalize facts only. One provider-neutral Email Shield core owns identity/provenance confidence, structural scam evidence, scoring, uncertainty, verdicts and product action policy. Repairs are split into reviewer-rejectable waves.

**Base:** `af48ed7d2b70b9233aba9595d08aa337cc6b7fbf`

**Approved design:** `docs/superpowers/specs/2026-08-16-universal-email-shield-repair-design.md`

## Global constraints

- Detection quality is an Email Shield property, never a mailbox/provider property.
- No provider-specific thresholds, Safe exceptions, scam vocabularies, brand rules or verdict forks.
- Missing/untrusted evidence is uncertainty; incomplete inspection never becomes Safe.
- Hard contradictions override relationship history and user trust.
- No threshold lowering, broad allowlists, test-only bypasses, production entitlement bypasses, or weaker SSRF/privacy controls.
- RED reproduction before production change; focused GREEN and regression review after each task.
- Full Windows/macOS/Linux Engineering Gate on frozen heads; merge only the exact verified SHA and independently gate merged `main`.
- Outlook live acceptance remains deferred until this program is green.
- Family Shield remains protected by real entitlement enforcement.
- Owner live reacceptance is consolidated and limited to changed workflows.

## Authoritative plan sequence

1. **Wave 0 + 1 — Universal detection integrity**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-0-1-detection-v2.md`
   - EMA-31, EMA-32, EMA-9, EMA-19, EMA-21.
   - Note: the earlier `...wave-0-1-detection.md` draft is superseded by this v2 and must not be executed.

2. **Wave 2 — Link and destination integrity**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-2-links.md`
   - EMA-7, EMA-10.

3. **Wave 3 — Protection lifecycle and release-mode integrity**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-3-protection-release.md`
   - EMA-18, EMA-23; provides authoritative state needed by EMA-26.

4. **Wave 4 — Message actions and mailbox lifecycle**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-4-actions-lifecycle.md`
   - EMA-8, EMA-6, EMA-16, EMA-25.

5. **Wave 5 — Diagnostic truth**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-5-diagnostics.md`
   - EMA-5, EMA-20.
   - Draft PR #102 is reviewed/rebased only after repaired workflow ownership is stable; it is not trusted or merged wholesale.

6. **Wave 6 — Health and consumer composition**
   - `docs/superpowers/plans/2026-08-16-universal-repair-wave-6-consumer.md`
   - EMA-17, EMA-15, EMA-11, EMA-12, EMA-13, EMA-26, EMA-27, EMA-28, EMA-29, EMA-30, EMA-24, EMA-22.

## External acceptance after code closure

- EMA-14: real Family entitlement acceptance; no bypass.
- Outlook/Microsoft: deliberate live acceptance using the owner's Microsoft developer access only after the universal repair program is green.

## Program completion gate

EMA-33 is DONE only when every confirmed code/workflow defect above is root-fixed and regression-locked, equivalent normalized evidence produces equivalent Email Shield decisions across provider adapters, already-working security/privacy behavior remains green, the exact repair head and exact merged `main` pass the full three-OS gate, and only deliberate external acceptance remains.