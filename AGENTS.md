# AGENTS.md

Conventions for anyone — human or AI coding assistant — contributing to this repository.

## This is a public repository

`Jakapil.Capture` is an open-source SDK published to nuget.org and consumed by developers worldwide.

**Everything user-visible must be written in English.** This is non-negotiable and applies to:

- `README.md` and any other documentation
- Code comments and XML doc comments
- Runtime-emitted strings — logger messages, exception messages, validation failures. These land in the
  consumer's logs and are the most visible surface of all.
- NuGet package metadata (`Description`, `PackageTags`, release notes)
- Commit messages, branch names, PR titles and PR bodies
- GitHub issues, releases, and discussions

The one deliberate exception is **sample data**: non-ASCII personal names such as `"Ayşe Yılmaz"` are used
as test fixtures precisely because they exercise non-ASCII PII handling. Those are data, not documentation
language — leave them as they are.

> If the conversation that produced a change was held in another language, translate before writing to the
> repository. The language of the discussion never determines the language of the code.

The private cloud-side repository has different conventions — do not carry them over here. In particular,
do not quote its internal ADR documents verbatim; paraphrase the requirement in English and keep the
`ADR-000X §Y` citation as a pointer.

## Build discipline

`Directory.Build.props` sets `TreatWarningsAsErrors=true` and `Nullable=enable`. **A warning is an error.**
Never silence one with `#pragma warning disable` or `<NoWarn>` — fix the root cause.

```bash
dotnet build          # must be 0 warnings / 0 errors
dotnet test           # xUnit; no external dependencies required
dotnet pack -c Release -o artifacts
```

## Invariants

1. **The wire contract is append-only.** `Jakapil.Capture.Contracts` types are a public versioned contract
   consumed by a server that also talks to older SDK versions still deployed in the field. Never remove or
   rename a field; add new ones as optional.
2. **The anonymization key never leaves the customer process.** It is read from an environment variable
   (`JAKAPIL_ANON_KEY` by default) and is never transmitted, logged, or written to disk. Anything derived
   from it that does leave the process must be an irreversible digest.
3. **Fail closed on classification.** A field that cannot be confidently classified is never left as
   plaintext. If you add a passthrough exception, it must be narrow, name-based, and gated — and it needs a
   concrete, documented case behind it, not speculation.
4. **The SDK runs inside the customer's request path.** Treat it as a hot path: avoid allocations in
   per-request code, never block, and never let a capture failure surface as a failure of the host request.
5. **Determinism.** The same input plus the same key must always produce the same output. No clocks, no
   randomness in the transform path.

## Versioning and publishing

Version lives in `Directory.Build.props`. Bump it in the same commit as the behavior change it describes.

Once a version has been packed into `artifacts/` or restored anywhere, do **not** repack that same version
with different content — the local NuGet cache will keep serving the old payload. Bump the patch version
instead.

The `README.md` is embedded in the package and cannot be corrected after publishing. Update it **before**
bumping the version, not after.
