# Triaging detection forensics

[← Back to README](../README.md)

The **Detection forensics** card on `/admin/ui/security` (and `GET /admin/api/v1/detections`)
answers one question: *why was this request redacted, and where did the value come from?* It
records shape, not content - use it to investigate, never to look up a secret.

| Column | Meaning |
|---|---|
| **Time / Req / Route** | When, which request id, which route. `Req` links to `/admin/activity`. |
| **JSON path** | Where the detection fired (`$.messages[0].content`, `$.api_key`, ...). |
| **Layer** | Scanner that produced it: `field`, `format`, `context`, `entropy`. |
| **Kind** | Detector family (`openai`, `github`, `api_key`, `key_in_text`, `suspicious_key`, ...). |
| **Pattern** | `-` for `field`/`entropy` (no shape). `context` shows the identifier, separator and quote that matched (`token =`, `token : "`, `password = '`). `format` rows show the shape inherited from an overlapping context finding at the same offset. The **shape**, never the value. |
| **Len** | Length of the masked span (the union when candidates overlap). For merged rows it is not the detector match length. |
| **Fingerprint** | 8 hex chars of an HMAC keyed per process. |

**Overlaps are unioned.** When two detectors find overlapping candidates, the surviving
finding grows to cover the other one's tail: **overlapping candidates are merged and the
union is masked**, so the proxy never masks less **at the span level** - the union is never
shorter than any single detector's match. Base64 and allow-list exemptions are still
evaluated on the merged span, but a span that covers a `format` finding is **never**
exempted. `Len` is therefore the length of the span actually masked - for merged rows it is
not the detector match length.

**Allow-list + union trade-off (accepted).** The allow-list is evaluated against the **merged**
span, so a `context`/`entropy` union that matches an `allow` pattern exempts the whole span -
including the part only the entropy scanner would have flagged (an isolated entropy finding there
might not have been exempted). The reverse direction is closed: a span that covers a `format`
finding is never exempted. This is the accepted side of "never mask less at the span level".

**Inheritance needs the same offset.** A `format` row only inherits `name`/`sep`/`quote` when the
discarded `context` finding starts at the **same** offset. When the `context` match starts *before*
the `format` one (e.g. `token:=<value>`), the surviving layer is `context` and it keeps its own
shape; there is no inheritance to do. The offset difference comes from the `=`: the `context`
separator group matches only `:`, while the value character class includes `=`, so the `=` is
absorbed into the `value` group and the value starts on the `=` - one character before the real
secret, which makes `Len` one longer and masks the `=` as well.

**Group by fingerprint, not by row.** The same value gives the same fingerprint within one process
run; ten rows with one fingerprint are one secret re-sent ten times, not ten secrets. The key is
ephemeral, so compare within a session, never across restarts. Same fingerprint ⇒ (almost certainly)
same value within the process; **the reverse is not guaranteed** - the same secret can get different
fingerprints when the masked span differs (`field` hashes the whole value, while
`bearer`/`url_cred`/`db_conn` hash only group 2).

**Read the layer before worrying.** The confidence order applies **at the same offset** (the
merge sorts by start first): `format` > `field` > `context` ≈ `entropy`
(`context` and `entropy` are both Medium, and the merge prefers `context` on a tie).
`format`/`field` are actionable (a known shape or a sensitive field name was masked - rotate it if
real); `context`/`entropy` are heuristics and can fire on legitimate text. Length is a quick sanity
check: OpenAI/Anthropic keys are 51/100+ chars, GitHub classic PATs 40, `github_pat_` 93, AWS access
key id 20, Google API keys 39 - an 8–9-char `Len` in `context` is usually a false positive **when the
pattern is not `password`/`secret`** - an 8-char password is exactly what this layer exists to catch.

**Use the path to find the origin.** `$.messages[N].content` is client-supplied history (pasted in
the prompt, or read from a file/tool result) - the common case. `reasoning`/`reasoning_details` is
model output, and OpenRouter duplicates the reasoning text in two fields, so one echo appears
twice. A field path (`$.api_key`, `$.headers.authorization`) means a JSON/config object carried it.

**Correlate.** Take `Req` to `/admin/activity` for the client, model, status and the surrounding
timeline. The same fingerprint in consecutive requests from one client means the same value is
replayed every turn in the agent's history.

**Going further without revealing anything.** Locate the source by *name*, with counts only:

```powershell
rg -c "token|secret|password|api_key|access_key" src\
```

The pattern must mirror the detector's name list (`token`, `secret`, `password`, `api_key`,
`access_key`, `credential`, `authorization`, ...). A bare `key` is **not** detected - `x:Key` in
XAML or `myKey` alone never fires. A false positive observed live: unquoted assignments in source
code (`var token = …`, `$token = …`) fire `context` with `name=token` even though the right-hand
side is not a credential - the `Pattern` column (`token =`) is how you spot it. If the fingerprint
always returns at the same path, a persistent file is in the agent's context: fix it at the source.
`format`/`field` -> rotate the credential. Benign and stable `context`/`entropy` -> add a
`Redaction.allow` regex.

**What the proxy will not do.** There is no "reveal" action and no stored value, prefix, suffix or
snippet - by design: crash dumps and dashboard logs would become a second copy of every secret;
XSS, a shared screen or DevTools would expose it in the UI; and the buffer would retain personal
data the proxy has no business keeping. Never ask an agent to print a detected value to "check"
it: the agent's context and the shell output are exactly the channels the proxy protects.

**Reducing noise.** The `context` layer minimum length (8 today) is **not configurable** - changing
it requires a code change and a rebuild, so it is not a runtime knob. `Redaction.allow` is the
targeted option and applies only to `context`/`entropy` - the `format` and `field` layers are never
exempted, and neither is a merged span that covers a `format` finding. The `name=` base64 exemption
is name-exact as well: a prefixed/suffixed identifier (`OPENAI_API_KEY=`, `MY_SECRET_KEY=`,
`x-SECRET_KEY=`) is not a whitelisted name, so a long base64-looking value after it stays a payload
and produces no row at all - by design.
