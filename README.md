# Jakapil.Capture

**Jakapil Capture** is an ASP.NET Core middleware SDK that captures HTTP traffic from running
.NET APIs. You add it to your application as a single line of middleware; it captures incoming
requests, outgoing responses, and correlation signals in the background — without blocking the
request path — and exports them to a Jakapil collector.

The captured traffic is turned into self-verifying test scenarios on the Jakapil side. The
middleware is designed to be safe under production load: the response always streams to the client
without buffering, the capture copy is bounded, and the queue drops the oldest entries under
backpressure (it never blocks the request pipeline).

## Installation

```bash
dotnet add package Jakapil.Capture
```

## Usage

Register the service and add the middleware to the pipeline in `Program.cs`:

```csharp
builder.Services.AddJakapilCapture(
    ingestKey: builder.Configuration["Jakapil:Capture:IngestKey"]!,
    collectorUri: "https://collector.jakapil.example");

// ...

app.UseJakapilCapture();
```

`ingestKey` is your ingest key and is sent to the collector verbatim in the `X-Jakapil-Key`
header — so it must be supplied **only through an environment variable / secret** and never
hard-coded. `collectorUri` is the collector address where captured interactions are sent.

If you need finer control, you can use the overload that takes an `Action<JakapilCaptureOptions>`:

```csharp
builder.Services.AddJakapilCapture(options =>
{
    options.IngestKey = builder.Configuration["Jakapil:Capture:IngestKey"]!;
    options.CollectorUri = "https://collector.jakapil.example";
    options.SampleRate = 0.25;
});
```

## Configuration options

| Option | Type | Default | Description |
|---|---|---|---|
| `Enabled` | `bool` | `true` | Main on/off switch. When `false`, the middleware is a pure passthrough. |
| `SampleRate` | `double` | `1.0` | The fraction of requests to capture, `[0, 1]`. `1.0` = capture everything. |
| `CollectorUri` | `string?` | `null` | The root address of the collector where captured interactions are sent. If left empty, the export worker stays idle. |
| `IngestKey` | `string?` | `null` | The raw ingest key sent to the collector in the `X-Jakapil-Key` header. |
| `MaxInlineBodyBytes` | `int` | `1048576` (1 MiB) | Bodies at or below this size are captured inline; larger ones are truncated and flagged as `Truncated`. |

Other settings (`MaxCapturedResponseBytes`, `StreamingContentTypes`, `QueueCapacity`,
`SensitiveHeaderNames`, `CorrelationHeaderNames`, `ExportBatchMaxItems`,
`ExportFlushIntervalSeconds`) ship with sensible defaults; see the `JakapilCaptureOptions`
XML documentation comments for details.

## Field anonymization

When `AnonymizationOptions` is configured with a key (`JAKAPIL_ANON_KEY` by default), every captured
request/response leaf is classified and transformed before it leaves your process — no raw production
value (name, email, password, flow identifier, ...) is ever sent to the collector. See
`Jakapil.Capture.Anonymization.FieldClass` for the four possible outcomes (`SafeLiteral`,
`FlowFingerprint`, `SyntheticPii`, `SecretTombstone`) and `AnonymizationOptions.FieldPolicy` for the
customer override that always wins over the built-in rules below.

### Identity, correlation, and auth-binding fields are anonymized too

Earlier releases of this SDK only ran the classifier above over the `Request`/`Response` body,
route/query parameters, and the allowlisted headers. The identity and correlation data every
captured interaction also carries — `Identity` (`SubjectId`, `UserName`, every claim), `Correlation`
(`SubjectId`, `SessionCookieId`, `ClientConnectionId`, `CustomCorrelationHeader`), and
`AuthBinding.SubjectId` — passed through untouched. With a key configured, a JWT `sub`, a username,
and every claim your identity provider issues went to the collector as plaintext even though the
request/response body was fully anonymized alongside it.

`Anonymizer.Anonymize` now covers those three blocks too, using the exact same one-way HMAC
fingerprint as the rest of this SDK — same key, same `Scope`. The three copies of a subject id that
appear across `Identity`, `Correlation`, and `AuthBinding` are guaranteed to fingerprint to the
**identical** value, so correlating a user across all three survives anonymization. The scheme
identifier reported in `CapturedInteraction.Anon` changed to reflect the wider coverage — this is a
purely declarative marker (the collector never compares it against anything) whose only purpose is
telling the cloud side "this payload's identity fields are covered too".

**Role claims are the one deliberate exception** — a claim named `role`, or the ASP.NET Core role
claim URI, is still sent as plaintext. A role (`Administrators`, `Support`) is an authorization
category, not something that identifies a person, and the set of roles in a typical application is
small enough that a fingerprint over it would be reversible by dictionary attack anyway — hiding it
buys little privacy while destroying a signal a role-aware test-user matching feature would need
down the line. Every other claim your identity provider issues — including ones this SDK doesn't
recognize — is fingerprinted; an unrecognized claim type is treated as potentially identifying, never
assumed safe.

As before, with no anonymization key configured, none of this runs: the whole interaction — body,
route/query, and now these identity/correlation fields too — passes through unchanged, and you still
get the startup warning about running in pass-through mode.

### Generic `name` is context-sensitive (since v1.2.0)

Strong-signal person-name fields (`fullName`, `firstName`, `lastName`, `surname`, ...) are **always**
synthesized, in every context. The bare, generic field `name`, however, is ambiguous on its own — a
`GET /api/catalog-types` response with `{ "catalogTypes": [ { "name": "Mug" }, { "name": "T-Shirt" } ] }`
is not personal data, but earlier versions treated it exactly like `fullName` and rewrote every category
label to a synthetic person name (e.g. `"Sage Blake"`). Scenarios built from that capture then asserted
the wrong literal on every replay against the live API — a guaranteed, reproducible false regression, not
a real product bug.

As of v1.2.0, a bare `name` field is only classified as PII (`SyntheticPii`) when the JSON object that
directly contains it has a field name that itself suggests a person or contact record — e.g.
`$.customer.name`, `$.billingAddress.name`. With no enclosing object (a root-level `name`) or a
non-person parent (`$.catalogTypes[].name`, `$.products[].name`), the value passes through unchanged as
`SafeLiteral`. **Plural collection endpoints are recognized too** — `$.users[].name`,
`$.customers[].name`, `$.employees[].name` all still resolve to `SyntheticPii` (a simple, deterministic
singularization is tried against the person-context word list — no inflection library, no IO) — this
matters because a plural collection is the single most common REST shape a person record appears in.

**Privacy trade-off.** This intentionally loosens the default: false positives (real, non-personal labels
rewritten as fake names) become rarer, but so does the safety margin — a field literally called `name`
that *does* hold a person's name, under a parent object this heuristic does not recognize (an unusual or
customer-specific schema), will now be sent as plaintext instead of being synthesized. The singularization
step is deliberately biased toward over-matching, not under-matching: a made-up plural that happens to
singularize into a listed word gets anonymized unnecessarily (recoverable via `FieldPolicy`), which is
preferred over the alternative of missing a real one (unrecoverable — the value is already off your
machine). If your API uses bare `name` for personal data in a context not covered by the built-in list
(`user`, `customer`, `person`, `contact`, `member`, `employee`, `account`, `buyer`, `seller`, `recipient`,
`sender`, `owner`, `author`, `patient`, `client`, `guest`, `subscriber`, `profile`, `billing`, `shipping`,
`address` — singular or plural), set it explicitly via `FieldPolicy`:

```csharp
options.Anonymization.FieldPolicy["name"] = FieldClass.SyntheticPii;
```

`FieldPolicy` always takes priority over every built-in rule, including this one.

### Type-preserving replacement values (since v1.2.0)

Whatever a leaf's JSON type was, its replacement keeps that type — a JSON *number* is replaced by a
synthetic *number* (never a quoted string), a JSON *boolean* is never replaced at all (booleans are
never ambiguous), and a JSON *string* is replaced by a synthetic *string*. Classification is unaffected
by this guarantee — an unrecognized field still fails safe to `SyntheticPii` exactly as documented above;
only the **shape** of the replacement value changes to match what it is standing in for. Two concrete
consequences:

- A numeric field with no recognized name (e.g. a custom `batchCount` query parameter) used to
  synthesize to alphanumeric text (`synthetic-77598c5712fd`), which many APIs' model binders reject
  outright (`400 Bad Request`) — breaking replay while still hiding nothing useful. It now synthesizes to
  numeric text instead (still non-reversible and non-correlatable outside its key/scope), so the request
  stays valid. Route, query, and header values are always *text on the wire* (there is no JSON container
  type at those positions), so "type" there means the replacement must still *parse* as the original kind
  — a numeric query parameter synthesizes to digits, a `true`/`false`-shaped one synthesizes to
  `true`/`false`.
- A JSON body number classified `SyntheticPii` (via an explicit `FieldPolicy` override — the built-in
  fail-safe never routes a bare number there on its own) is written back as an unquoted JSON number, not a
  quoted string, and stays integral when the original had no fractional part. The synthetic magnitude is
  always bounded well within a 32-bit integer's range, regardless of how large the original value was.

This does **not** change how `FlowFingerprint` (`fp:...`) and `SecretTombstone` (`jkp:tomb:...`)
envelopes are written for a JSON body leaf — those remain textual by design, and the envelope grammar
itself already records the original JSON type as an embedded tag (`fp:n:...`, `jkp:tomb:n:...`) for the
server side to use. The one passthrough exception is described next.

### Pagination/counter query, route, and header values pass through unchanged (since v1.3.1)

`page` and `limit` have always been `SafeLiteral` (see the built-in allowlist above), but a request like
`GET /api/catalog-items?PageSize=10&PageIndex=0` used to have its `PageSize`/`PageIndex` values
anonymized into a **different** number (e.g. `?PageSize=35&PageIndex=1`) — neither name was recognized,
so both fell to the unknown-field fail-safe (`SyntheticPii`). Type-preservation (above) kept the
replacement numeric so the target's model binder still accepted it, but the *value itself* changed,
which silently corrupts the request's meaning: a scenario built from that capture keeps asking for page
35 instead of page 0/10, and a size-dependent assertion (e.g. "response has 10 items") fails forever
against a live re-run, even though nothing about the target actually broke.

As of v1.3.1, these English pagination/counter names are recognized as `SafeLiteral` **only when they
appear as a route, query-string, or header value** — never in a JSON body — and only when the raw text
still looks like the number it claims to be:

`pageSize`, `pageIndex`, `pageNumber`, `perPage`, `offset`, `skip`, `take`, `top` (plus the
pre-existing `page`/`limit`) — matched case-insensitively and independent of separators, so
`page_size`, `page[size]`, `$top`, and `_limit` all resolve to the same recognized name.

Two things deliberately still apply on top of a name match:

- **Shape gate.** The value must actually look numeric (`SyntheticPiiGenerator.DetectTransportShape`). A
  name/value mismatch — e.g. `?pageSize=ahmet@x.com` — does **not** take this exception and is
  anonymized exactly as before, so a field merely *named* like a counter can never leak free text this
  way. There is no upper bound on digit count — a legitimate `offset=1000000` still passes unchanged.
- **`FieldPolicy` always wins.** An explicit `AnonymizationOptions.FieldPolicy["pageSize"] = ...` entry
  overrides this default exactly like every other built-in rule.

**Non-English pagination names are not covered.** A parameter named `sayfaBoyutu` or `kayitSayisi`
normalizes to a token this list does not contain, so it still falls to the unknown-field fail-safe
(shape-preserved synthesis, not plaintext passthrough). If your API uses non-English (or otherwise
unlisted) pagination/counter names and you want them to pass through unchanged too, the escape hatch is
the same `FieldPolicy` override:

```csharp
options.Anonymization.FieldPolicy["sayfaBoyutu"] = FieldClass.SafeLiteral;
```

Also deliberately **not** included: `sort`, `order`, `orderBy`, `direction`, `asc`, `desc`. No concrete
failure has been reported for these, and `order` in particular can hold a business reference (e.g.
`"ORD-2024-000123"`) rather than a sort direction in some APIs — widen this list only for a documented
case, via `FieldPolicy`, not speculatively.

## Signed replay-request verification (since v1.2.0)

When the Jakapil Runner re-runs a scenario against your API (a test run), it can attach a cryptographically
signed `X-Jakapil-Replay` header to each request. When this SDK verifies that signature, two things happen to
that request that never happen for ordinary traffic:

1. **It is never captured/exported.** Replay traffic would otherwise pollute your captured corpus with its own
   test data, so a verified replay request is unconditionally excluded from capture — independent of
   `SampleRate` or even `Enabled`.
2. **The response body is masked on the way out**, using the exact same anonymization key, `Scope`, and field
   classification as ordinary capture-side anonymization (see "Field anonymization" above) — so your API's
   *live* production-shaped response ("Mug") comes back anonymized ("Sage Blake") exactly like the *captured*
   corpus value it is being compared against, letting equality-style assertions built from anonymized capture
   data pass against a live re-run without ever exposing what your API actually returned. One exception: fields
   correlating one response to the next request in the same scenario (order id, created resource id, ...) are
   left as their live value, because the Runner needs the *real* identifier your API produced to keep chaining
   requests correctly — masking those would break the scenario, and they carry no personal content of their own.
   This live value is written back with its **original JSON type intact** (since v1.2.0) — a numeric id stays
   a JSON number, never a quoted string — so a scenario's schema assertion (`{ id: Number }`) still passes
   against the masked replay response exactly as it would against the real one.

### Run-issued credentials pass through live too (since v1.2.0)

The same problem that justifies the FlowFingerprint exception above also applies to a login/session response: a
`token` field used to come back as a `jkp:tomb:s:token` marker, which the Runner cannot inject into the next
step's `Authorization` header — no authenticated scenario could ever be replayed. As of v1.2.0, a field whose
name's semantic kind is **`token`, `session`, `cookie`, `csrf`, or `cursor`** — matched on the TRAILING
camelCase/snake_case word, e.g. `token`, `authToken`, `sessionToken`, `csrfToken`, `nextCursor` all match
(`sessionId` does not — its trailing word is `id`, already covered by the pre-existing FlowFingerprint
passthrough) — also passes through **live**, for the identical reason FlowFingerprint does: the target produced
it during this run, and the Runner needs the real value to keep the scenario going. This pre-empts whatever
classification the field would otherwise have received — most commonly `SecretTombstone`, since `token`/`cookie`
are also secret field names.

Two response **headers** get the same treatment: `Set-Cookie` and `Location` — the two places a run-issued
session identifier or a newly created resource's address are most likely to appear outside the body.

**`password` never passes through, by construction** — it is not, and never will be, one of the five allowlisted
words, so an echoed password field stays tombstoned exactly as before. A compound name like
`passwordResetToken` *does* pass through (its trailing word is `token`) — that field holds a token the target
issued during the run, not the password value itself, which is the correct call under the same rule.

`FieldPolicy` is still the escape hatch and always wins: an explicit override for a field or header name (e.g.
`options.Anonymization.FieldPolicy["token"] = FieldClass.SecretTombstone;`) is honored instead of the
RunCredential default, for both JSON leaves and the two headers.

### Idempotent replay masking (since v1.2.0)

Masking a replay response used to be a one-way street: if the Jakapil Runner sent a synthetic value from its
corpus (say, a synthesized name) and your API validated and echoed it straight back, this SDK — seeing that
echoed text as if it were fresh production data — synthesized it *again*, seeded off the synthetic text itself
rather than the original raw value, producing a **second, different** synthetic value. Every echo-equality
assertion built from the corpus then failed structurally, even though your API's behavior never changed.

As of v1.2.0, replay masking recognizes two shapes of "already anonymized" data and passes them through
byte-identical instead of re-masking them:

- A well-formed `fp:`/`jkp:tomb:` envelope, regardless of which field it currently sits under (an envelope
  echoed back under a different field name than the one that produced it is still recognized by its own shape).
- A value that already matches the exact deterministic output format of this SDK's own synthetic generators
  (email/phone/name/free-text/generic) — checked only against the ONE generator the field's own name would
  select, never a blanket "looks synthetic" scan, to keep false positives bounded.

This recognition only ever runs in the replay masking path — capture-side anonymization is completely
unaffected, and a genuine production value is still synthesized exactly as before. It is deliberately
conservative: numeric and boolean synthetic values are **never** recognized this way (there is no reliable way
to distinguish a synthetic number from a real one by format alone), so an echoed numeric/boolean `SyntheticPii`
field can still re-synthesize to a different value on replay — a narrower, documented gap rather than a silent
one, and the rarer fallback-only case in practice.

### The masking-confirmation header, in full (since v1.2.0)

```
X-Jakapil-Masked: v1;scheme=<scheme>;keyVersion=<n>[;body=unmasked-nonjson][;live=<path>(,<path>)*][;liveHeaders=<name>(,<name>)*]
```

`scheme`/`keyVersion` are unchanged from before v1.2.0. `live=` and `liveHeaders=` arrived in v1.2.0; `body=`
in v1.2.1. All three are appended only when there is something to declare — an ordinary JSON response with no
RunCredential leaves produces the exact same header as before:

- **`body=`** (since v1.2.1) — declares that the response body could not be masked and was forwarded
  **unchanged**. The only
  value this SDK version ever emits is `unmasked-nonjson`: the response's `Content-Type` was not JSON, so there
  is no safe, general way to anonymize it — exactly the same reasoning capture-time anonymization already
  applies to a non-JSON request/response body (ADR-0002's field classification is defined over named JSON
  leaves, not arbitrary text/binary blobs; capture keeps the body as-is for the same reason). This field is
  **omitted** on the ordinary JSON-masked path rather than always being emitted with an explicit `body=masked`
  counterpart — that keeps the header byte-for-byte identical, for every case that already worked, to what it
  was before this field existed, and matches the receiver's documented default: **absent `body=` means
  masked**. A malformed JSON body (`Content-Type` says JSON, but the bytes fail to parse) and a truncated body
  (the response exceeded `Replay.MaxMaskedResponseBytes`) are both **different** from this case and do **not**
  get this field, or any header at all — see below.
- **`live=`** (since v1.2.0) — a comma-separated list of JSONPaths (root-relative, `$`) naming every response-body leaf that
  passed through live via the RunCredential mechanism above. Object property access is `.name`; an array
  contributes a single `[*]` wildcard covering every element, not one entry per index. A property name that
  isn't a simple `[A-Za-z_][A-Za-z0-9_]*` identifier is percent-encoded (`Uri.EscapeDataString`, plus an
  explicit `.`→`%2E` substitution for the one delimiter that function leaves unescaped) so it can never collide
  with the `.`/`,`/`;` grammar delimiters — decode with `Uri.UnescapeDataString`. FlowFingerprint passthrough
  leaves (the pre-existing ADR-0003 §5 behavior) are **not** included here; this field is scoped to the new
  RunCredential category only.
- **`liveHeaders=`** (since v1.2.0) — a comma-separated list of header names (never encoded — an HTTP header name cannot
  contain `,`/`;`) that passed through live; only ever `Set-Cookie` and/or `Location`.

Examples: `v1;scheme=hmac-sha256-v1;keyVersion=1` (nothing to declare) ·
`v1;scheme=hmac-sha256-v1;keyVersion=1;body=unmasked-nonjson` (non-JSON body, forwarded unchanged) ·
`v1;scheme=hmac-sha256-v1;keyVersion=1;live=$.token;liveHeaders=Set-Cookie` ·
`v1;scheme=hmac-sha256-v1;keyVersion=1;live=$.auth.sessionToken,$.items[*].cursor`.

The header is **absent** — fail-closed, exactly like before v1.2.0 — for every case where the response body
could not even be classified, as opposed to being deliberately non-JSON: a malformed JSON body (`Content-Type`
claims JSON, parsing fails) and a body that was truncated for exceeding `Replay.MaxMaskedResponseBytes` (see
"Configuring it" below) both fall into this bucket. In both cases the live, unmodified bytes are still
forwarded to the caller — only the confirmation header is withheld, so the Jakapil cloud side never mistakes an
unclassifiable body for one it can safely persist.

When the header is absent, malformed, expired, replayed, or fails to verify for any reason, **behavior is
byte-for-byte identical to today**: no masking, no capture suppression, no error response. The signature is
purely a behavior switch — it never grants any extra authority over the request, which still goes through your
application's own authentication/authorization exactly as if the header were not there.

### Configuring it

Signed replay verification is off by default in the sense that matters: with no public key configured, there is
nothing to verify against, so it costs nothing and does nothing. To turn it on, add the public key(s) the
Jakapil panel gives you for this project/environment:

```csharp
builder.Services.AddJakapilCapture(options =>
{
    options.IngestKey = builder.Configuration["Jakapil:Capture:IngestKey"]!;
    options.CollectorUri = "https://collector.jakapil.example";

    options.Replay.PublicKeys = [builder.Configuration["Jakapil:Capture:ReplayPublicKey"]!];
    options.Replay.ExpectedTenantId = "...";       // optional — see below
    options.Replay.ExpectedEnvironmentId = "...";  // optional — see below
});
```

- `Replay.PublicKeys` accepts each key as either PEM (`-----BEGIN PUBLIC KEY-----...`) or a single-line
  base64(DER) string — both are `SubjectPublicKeyInfo`-encoded ECDSA P-256 keys, never a secret (only Jakapil
  holds the matching private key, so configuring this does not require any secret handling on your side).
  Multiple keys can be listed at once — this is how key rotation works without downtime: Jakapil starts signing
  with a new key while the old one is still listed here, and you remove the old entry once the rotation window
  has closed.
- `Replay.ExpectedTenantId`/`ExpectedEnvironmentId` are optional extra binding checks — when set, a signature
  for a different tenant/environment id than configured here is treated as invalid. They are independent of
  `Anonymization.Scope` (that field feeds HMAC domain separation, a different concern with a different
  correctness bar — changing it changes every synthetic value you have ever seen, so replay identity binding
  deliberately gets its own, separately-optional fields instead of reusing it). **Leaving them unset is not
  wide open** (the key ring is still per-project), but it does mean a run signed for one environment could be
  replayed against a different instance of the same project sharing the same public key. The real protection
  for production is the switch below, not these fields — a production deployment should keep replay
  verification disabled outright rather than relying on `ExpectedEnvironmentId` alone.
- `Replay.ClockSkewTolerance` (default 300s), `Replay.NonceCacheSize` (default 10,000), and
  `Replay.MaxMaskedResponseBytes` (default 8 MiB — the hard cap on how large a live response this SDK is
  willing to buffer in order to mask it) all have sensible defaults; see `ReplayVerificationOptions`' XML
  documentation for details on when you would want to change them.
- Set `Replay.Enabled = false` (or simply never configure `Replay.PublicKeys`) to keep verification off in a
  given environment — **production deployments should do this**, since replay verification is designed for
  the staging/test targets the Jakapil Runner actually replays scenarios against (see the "privacy guarantee"
  section below for why a clean, non-production target matters here regardless).

### Cross-implementation test vectors

The Jakapil Runner builds the ADR-0003 §6.2 canonical signature string INDEPENDENTLY of this SDK — the two
implementations never share code, only the spec. A one-character format drift between them (field order, an
escaped vs. raw route character, a missing byte in the body hash, ...) makes every signature invalid in the
field, silently, with no error surfaced anywhere except "replay behavior never activates". To catch that class
of bug before it ships, this repo publishes
[`tests/vectors/replay-signature-vectors.json`](tests/vectors/replay-signature-vectors.json): a golden fixture
of several representative requests (empty body, a JSON body, a body with multi-byte UTF-8 characters, a query
string with percent-encoding, an unusual HTTP method) together with their exact canonical strings, body hashes,
and — signed with a fixed, clearly-marked **TEST-ONLY** ECDSA key pair committed in the same file — valid
signatures over them. Any independent implementation (the Jakapil Runner's, or anyone else's) can recompute the
canonical string for each case from its recorded inputs and compare it byte-for-byte against the recorded value,
and/or verify the recorded signature against the recorded public key, to prove interoperability without needing
a live end-to-end run. `ReplaySignatureVectorsTests.cs` in this repo's test suite does exactly that against this
SDK's own implementation, so the fixture can never silently drift out of sync with the code that generates it.

### The privacy guarantee, precisely

A signed replay response never carries your API's actual production-shaped values (personal data, free text,
secrets) back to Jakapil — those are anonymized in exactly the same way, and to the same degree, as your
already-anonymized captured corpus. What it *does* carry back are the correlation identifiers your API itself
produced during that run (e.g. a newly created order's id), so Jakapil can keep chaining a multi-step scenario
correctly; this is only meaningful if the target you are running replay scenarios against is a clean,
isolated staging environment that never holds a copy of production data — see the "Field anonymization"
section and the ADR this feature implements for the full reasoning.

## Version history

Full notes for each release: https://github.com/jakapildev/jakapil-capture/releases

### 1.2.1

**Masking confirmation for non-JSON response bodies.** A signed-replay response whose `Content-Type` was not
JSON previously got **no confirmation header at all**, because masking never ran. The cloud side treats a
missing confirmation as "do not persist the body" — correct for privacy, but it meant such a step could never
be verified. A `409 Conflict` carrying a plain-text message is one of the most common error shapes in ASP.NET
(`Response.WriteAsync("…")` defaults to `text/plain` when no content type is set), so scenarios expecting a
4xx were silently unverifiable.

The confirmation header gained an optional `body=` field (see "The masking-confirmation header, in full"). A
non-JSON body is now forwarded unchanged **and that fact is declared honestly**, rather than passing through
in silence. The field is optional and absent means `masked`, so 1.2.0 and earlier receivers are unaffected.

Malformed JSON and truncated bodies deliberately still withhold the header — those are unclassifiable, not
merely non-JSON.

### 1.2.0

Signed replay-request verification with in-process response masking; context-sensitive classification of the
generic `name` field; type-preserving replacement values; run-issued credentials (`token`, `session`, `cookie`,
`csrf`, `cursor`) passing through live so multi-step scenarios keep chaining; idempotent replay masking; and
the `live=`/`liveHeaders=` declarations on the confirmation header.

## License

MIT
