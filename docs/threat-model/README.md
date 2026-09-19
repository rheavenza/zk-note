# Threat Model & Security Documentation

This directory contains the threat models, security reviews, and audit reports for the Zero-Knowledge Note-Taking application:

1. [Application Threat Model Review (`threat-model-review.md`)](./threat-model-review.md) — Comprehensive system threat model, trust boundaries, web-origin trust limitations, and residual risk assessment (ZK-097).
2. [Browser XSS & CSP Security Review (`web-security-review.md`)](./web-security-review.md) — Content Security Policy analysis, dangerous HTML rendering sink audit, and Markdown sanitization (ZK-094).
3. [Dependency & Supply-Chain Audit (`dependency-audit.md`)](./dependency-audit.md) — Supply-chain security, RustSec and npm audit reports, and cryptographic dependency review (ZK-093).
4. [CLI Editor Workflow Security (`cli-editor-security.md`)](./cli-editor-security.md) — Threat model for temporary local plaintext files during interactive `$EDITOR` sessions (ZK-053).
