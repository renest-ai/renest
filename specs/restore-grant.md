# restore-grant · the recovery-code contract

> Status: **v2 envelope over a v1 payload**. This file is the only authoritative
> text for recovery codes. Implementation: the service's grant router and grant
> schema; consumers: `renest/restore.py`, the escape hatch `restore.sh`
> (curl + jq), and later the desktop client and orchestrator.
> **A recovery code and a hand-off code are two different objects**: a recovery
> code is a machine-facing credential (this document); a hand-off code is an
> account-facing transfer token (issued and redeemed in the console, carries no
> download capability, never reaches a machine). Neither accepts the other, and
> mixing them is forbidden.

## 1. Three sentences (the user-facing wording, which comes before any field)

A recovery code is valid for a few days, binds the first machine that redeems it,
and you can revoke it at any moment. If it expires, you lose it, or you need it on
another machine, sign another one -- the nest stays in your account. As long as you
can log in, you can always sign a new code.

> The binding is real as of 2026-08-11, not a promise: the machine sends a hash of
> its own stable ids on redeem, the first one wins, and a different one is refused.
> Re-redeeming from the same machine is resumption and stays allowed. A code whose
> first redeem carried no machine id never binds -- there was nothing to bind to,
> and refusing would only lock out someone who legitimately holds the code.

## 2. The v2 envelope (what you get when you sign)

```json
{
  "grant_version": "2",
  "grant_id": "<ULID>",
  "nest_id": "<manifest.id, the content identity>",
  "issued_at": "<ISO8601>",
  "expires_at": "<ISO8601; lifetime is a business parameter, default 3 days, range 1h-30d>",
  "manifest_sha256": "<64hex>",
  "origin": "<service base URL; redemption and progress reporting share it>",
  "exchange_url": "<POST here to redeem the v1 payload>"
}
```

- **The envelope contains no pre-signed URL.** The code is a redeemable token
  held by the service; pre-signing is demoted to an implementation detail behind
  redemption.
- An older consumer that only understands v1 **must refuse a v2 explicitly**
  (major-version semantics, per the existing frozen-contract rule).
- The code is the credential (a ULID, not guessable). It can be revoked, after
  which redemption and progress reporting immediately return 410. Every
  redemption is audited server-side (count, time, address).

## 3. Redemption (machine side, no login)

`POST {exchange_url}` →

- `200`: **the frozen v1 payload** (§4), containing freshly minted short-lived
  pre-signed links (internally ≤6h, and never beyond the code's own remaining
  lifetime). Every redemption re-runs the supply checks, so content withdrawn
  after the code was signed cannot be redeemed.
- `410 GRANT_REVOKED / GRANT_EXPIRED`: sign another one; the nest has been in
  the account all along.
- `404 GRANT_NOT_FOUND`: unknown code.

**Resuming an interrupted restore** is simply redeeming the same code again:
files already verified in the journal are not re-fetched, and if the pre-signed
links expire mid-way they are redeemed again. One code, one run: progress
reporting uses `grant_id` as the run identity, idempotently.

## 4. The v1 payload (the redemption response; frozen, `extra=forbid`, not one field more or less)

```json
{
  "grant_version": "1",
  "grant_id": "<same as the envelope>",
  "nest_id": "<manifest.id>",
  "issued_at": "<time of this redemption>",
  "expires_at": "<expiry of these pre-signed links>",
  "manifest_url": "<pre-signed GET>",
  "manifest_sha256": "<64hex>",
  "blobmap": { "<sha256>": ["<primary source url>", "<second source url>", "…"] },
  "meta4": null,
  "handed_off_from": null,
  "handed_off_relayed": null,
  "retention_days_left": null
}
```

`handed_off_from` — **who handed this nest to you** (the sender's display name).
`null` or absent means you packed it yourself.
**This is a server-side fact**, taken from the transfer record written when the
nest was claimed, and **never from the manifest**: a thing being inspected must
not supply the rules for inspecting it, or a malicious nest declares itself
trustworthy and the check dissolves. The restore path uses this to take a
stricter posture toward someone else's nest (when a dependency source looks
wrong, it must name the sender as well as the domain; blanket overrides do not
apply to such nests). A locally self-signed payload omits the field, which means
"treated as your own nest, behaviour unchanged".

`handed_off_relayed` — **whether the person who gave it to you packed it or
merely passed it on** (`true` = they never packed this nest; they received it
from someone else and forwarded it). Meaningful only when `handed_off_from` is
present; `null` means unknown.
It defends against **laundering**: an attacker gives a poisoned nest to an
unwitting middleman, the middleman forwards it, and the recipient sees a name
they trust without knowing that person never packed it -- the name is real, the
trust is misplaced.
**Deliberately one bit, with no identity of the previous holder**: hand-offs are
private and the previous holder never agreed to be named; and since a sender
cannot see who received their nest, exposing the upstream in one direction only
would break that symmetry. One bit is enough for the recipient to ask "have you
actually checked this nest?", which is exactly the question we want asked.

`retention_days_left` — **how many days of free-tier retention the account that
signed this code has left**; `null` or absent means the rule does not apply
(paid tier, or the feature is off). Free-tier assets are kept for 90 days, and
**one login to the website** restarts the clock; recall e-mails begin at day 60.
The only reason this field exists is to close **a silent kill**: a free user may
well revive their setup from a pod with a recovery code every day and never open
the website, while renewal only counts website logins -- without a word at the
point of restore, they would be swept away while visibly still using the
product. Consumers **must** show the countdown when the value is `≤ 30`.
**Informs, never blocks**: this field never changes restore behaviour. A locally
self-signed payload omits it, so nothing is shown and behaviour is unchanged.

The v1 payload remains consumable as a standalone file (the CLI and the escape
hatch read it directly), so locally signed codes continue to be v1.

## 4.9 Why someone must sign on the escape hatch's behalf

This section is not background. It is the reason the recovery code **has to
exist**, written down so that a later reader does not see "another signing step"
and try to optimise it away.

**The escape hatch's dependency list is curl, jq, sha256sum (or shasum), tar and
uv. It contains no `openssl`, and it never will.** AWS SigV4 pre-signing needs
HMAC-SHA256, and **that set of tools cannot compute it**.

So the conclusion is structural, not a shortcut:

> **For bytes in a private bucket, the escape hatch can only ever consume a link
> signed elsewhere. It can never sign one itself.**

"Who signs" therefore splits into two paths, both producing **the same v1
payload** (§4):

| User | Who signs | How they get it |
|---|---|---|
| Has a Renest account | **The service** | v2 envelope → redemption (§3) |
| No account, own bucket | **Their own machine, where the key lives** | `renest presign --nest <id> --out code.json` |

The two paths are **completely equivalent to a consumer** -- which is exactly the
value of freezing the payload in §4: the escape hatch and the agent each need to
understand only one thing.

**Corollary (do not route around it)**: any design that hands the escape hatch a
bucket key so it can fetch bytes itself is wrong. It breaks the escape hatch's
dependency rule (it would need a new dependency) and it puts a long-lived key on
an execution host (breaking the credential rule). **Pre-signing is the only way
to fetch private-bucket bytes on an execution host.**

## 5. Consumer obligations

| Consumer | Obligation |
|---|---|
| `renest restore --grant <file/URL>` | v2 → redeem automatically; v1 → consume directly; expired pre-signed links → redeem again and resume; report progress to the `origin` recorded in the envelope; show the countdown when `retention_days_left ≤ 30` |
| `restore.sh` (escape hatch) | `GRANT=<file/URL>`: for v2, POST with curl to redeem and pull `manifest_url` / `blobmap` with jq; show the countdown when `retention_days_left ≤ 30`; depend on nothing beyond curl and jq |
| Orchestrator / desktop (later) | As the CLI; revocation must be respected (410 means stop; never cache old pre-signed links) |

## 6. Version history

- **2026-07-26 (second change)**: the v1 payload gained the optional field
  `retention_days_left` (free-tier lifecycle). **Purely additive**, so
  `grant_version` does not move -- an older consumer that does not recognise it
  ignores it. Unlike `handed_off_from`, it **changes no restore behaviour**; its
  only job is to put "N days left, log in to the website to renew" in front of
  the user at the moment of restore. The frozen field set grew by one, with the
  contract test updated in the same change.
- **2026-07-26**: the v1 payload gained the optional fields `handed_off_from` and
  `handed_off_relayed`. The trigger: an allowlist can stop "this nest wants to
  install from an unfamiliar server", but it cannot tell "I deliberately used my
  own private index" apart from "someone packed this maliciously and handed it to
  me" -- and treating both the same is the root cause of simultaneously blocking
  the innocent and missing the malicious. **Purely additive**: `grant_version`
  does not move, older consumers read by key and ignore what they do not know,
  and newer consumers tighten accordingly.
- **2026-07-24**: contract semantics pinned: `nest_id` **is `manifest.id`, the
  content identity, and never any database primary key**. The service stores this
  value, the client declares it at commit time, it is filled back in when a code
  is signed, and the restore side aligns its verification to it.
- **2026-07-23**: renaming batch. The content-identity field in the envelope and
  the v1 payload became `nest_id`; the old prefix retired. `grant_version` did
  not move -- with no real users, the break was clean and no compatibility alias
  was kept. All other fields stayed frozen.
- **2026-07-18**: the v2 envelope was introduced: a service-redeemable token, a
  parameterised lifetime defaulting to 3 days, revocable and auditable, with
  "single use" withdrawn from the contract. The v1 shape was demoted to the
  redemption payload and the local signing format, with its fields still frozen.
- **Early 2026-07**: v1, where signing produced pre-signed links directly. That
  issuing shape is abolished; its documentation lives in version history.
