Status: VERIFIED
# IC `read_state` (anonymous): module hash, controllers, Candid metadata

## Summary

`read_state` is the IC HTTPS interface call that returns a BLS-signed certificate over
selected paths of the replicated state tree. We use it, with the anonymous sender, to
read three facts about a canister: `module_hash` (SHA-256 of the installed Wasm),
`controllers` (who can upgrade it) and `metadata/candid:service` (its public Candid
interface, when the canister publishes it). The request and response encoding below was
checked against the current interface spec on docs.internetcomputer.org (the old
`internetcomputer.org/docs/references/ic-interface-spec` URL now 301-redirects there).
No request was sent to any IC boundary node while writing this note.

Recommendation: keep the existing manual path (`core/ic_encoding.py` + `core/ic_client.py`,
`cbor2` over the shared `core/http.py` client). Add hash-tree lookup and certificate
verification ourselves, and switch the endpoint from v2 (deprecated) to v3.

## Endpoints

From the HTTPS interface page:

| Path | Status in spec |
|---|---|
| `POST /api/v2/canister/<effective_canister_id>/read_state` | deprecated |
| `POST /api/v3/canister/<effective_canister_id>/read_state` | current |
| `/api/v2/subnet/<id>/read_state`, `/api/v3/subnet/<id>/read_state` | not used by us |

- Base URL: `https://icp-api.io` (current `DEFAULT_BOUNDARY` in `core/ic_client.py`).
- The body is CBOR. The spec says "POST requests with a CBOR-encoded request body" and names
  no Content-Type header. Agents send `Content-Type: application/cbor`, and we keep it.
- `<effective_canister_id>` is the textual id of the canister we inspect. The spec allows
  `/canister/<canister_id>/module_hash` and `/canister/<canister_id>/controllers` only when
  `<canister_id>` matches `<effective_canister_id>`. Every read_state call is therefore for
  one canister, and its paths must all name that same canister.
- v3 difference: for `/api/v3/canister/<ecid>/read_state`, `<ecid>` must fall inside the
  canister range of the certificate's delegation subnet. This is checked during
  verification (see below).
- `core/ic_client.py` currently posts to `/api/v2/...`. The collector task (T07) should
  move it to `/api/v3/...`. The v3 read_state response body has the same shape.

## Auth

None. The sender is the anonymous principal, a single byte `0x04` ("used for the
anonymous caller"). The spec says: "The fields `sender_pubkey`, `sender_sig`, and
`sender_delegation` must be omitted if the `sender` field is the anonymous principal."
We need no key material and store no key material. That fits the guardrails: no secrets,
and no identity that could sign an update call.

Authorization of paths for an anonymous sender:
- `module_hash` and `controllers`: allowed whenever the canister id equals the effective
  canister id.
- `metadata/<name>`: allowed if `<name>` is a *public* custom section (`icp:public <name>`).
  A *private* section (`icp:private <name>`) may be read only by a controller, so
  anonymous requests are not authorized for it.

## Rate limits

The interface spec publishes no numeric limits. It says only that a 4xx means a client
error, a 5xx a server error, and "Except for 429 HTTP status, retrying the request will
likely have the same outcome."
DFINITY staff on the forum (not normative): boundary nodes generally do not rate-limit
queries or reads, but they shed load at high utilization and temporarily ban sustained
traffic above about 1k req/s. Incident rate-limit rules come from an NNS-managed
rate-limit canister.
Collector policy: one read_state call per canister per run, all three paths in one
request, the SafeHttpClient's own throttle, and backoff on 429 and 5xx only.

## Request encoding (anonymous read_state)

Envelope (CBOR, wrapped in self-describe tag 55799, which the spec defines as "major type 6
... tag value `55799`, followed by a record"):

```
55799({
  "content": {
    "request_type":   "read_state",                 # text
    "sender":         h'04',                        # blob, anonymous principal
    "ingress_expiry": <uint, ns since Unix epoch>,  # now + ~4 min (we use 240 s)
    "paths": [                                      # array of paths; path = array of blobs
      [ h'63616e6973746572', <canister id bytes>, h'6d6f64756c655f68617368' ],
      [ h'63616e6973746572', <canister id bytes>, h'636f6e74726f6c6c657273' ],
      [ h'63616e6973746572', <canister id bytes>, h'6d65746164617461',
        h'63616e6469643a73657276696365' ]
    ]
    # "nonce" (blob, <= 32 bytes) is optional; we omit it.
  }
})
```

- Record keys are CBOR text strings (major type 3). Blobs are byte strings (major type 2).
  Arrays are major type 4. Path labels are always blobs: `b"canister"`, the raw principal
  bytes (not the text form), `b"module_hash"`, `b"controllers"`, `b"metadata"`,
  `b"candid:service"`. A label may contain `/`, because `/` is only notation and never
  appears in the encoding.
- Limits: at most 1000 paths per request, at most 127 labels per path.
- `read_state` content has no `canister_id` field (unlike `query`). The canister is
  identified by the URL and the path labels.
- Expiry: the IC "may refuse to accept requests with an ingress expiry date too far in the
  future"; the spec mentions a mainnet maximum near 5 minutes. For anonymous query and
  read_state requests "the IC may accept any provided expiry timestamp".
- Principal text to bytes: text = `Grouped(Base32(CRC32(b) . b))`. The text is RFC 4648
  base32 without padding, lowercase, with a dash every 5 characters. The CRC32 is
  ISO 3309 / ITU-T V.42 (the same as `zlib.crc32`), stored big-endian. To decode: remove
  the dashes, base32-decode, split off the first 4 bytes as the checksum, and check that
  re-encoding gives the same canonical text. Principals are at most 29 bytes. Spec
  example: `0xABCD01` <-> `em77e-bvlzu-aq`.
- Alignment with the code: `ic_encoding.build_envelope("read_state", ...)` and
  `principal_from_text` / `principal_to_text` already match all of the above.

## Library vs manual CBOR decision

| Option | Facts (2026-10-15) | Fit with our guardrails |
|---|---|---|
| `icp-py-core` (github.com/eliezhao/icp-py-core, PyPI) | Exists and is maintained: v1.0.0 2025-10-20 ... v2.3.1 2026-05-13; MIT; Python >= 3.8. A fork of ic-py. Deps: `httpx>=0.24`, `cbor2`, `ecdsa`, `PyNaCl`, `ic_candid_parser` (Rust). Optional `bls` extra = `blst`, though the README describes building the supranational binding by hand. Supports anonymous `Identity(anonymous=True)`, uses v3 endpoints, verifies certificates by default for update calls. The README documents no high-level helper for module_hash/controllers/metadata. | Poor. It brings its own httpx client (breaks the "only `core/http.py` imports httpx" rule and bypasses the allowlist), plus `Agent.update()` and signing identities (breaks query-only guardrail 1 at the dependency level), plus signing crypto we do not need. |
| `ic-py` (rocklabs-io / PyPI `ic-py`) | PyPI's latest is 1.0.1 (2022-06-23). The GitHub repo is still active (MIT) and has optional BLS verification on `update_raw(verify_certificate=...)`, which needs a blst binding that is "not on PyPI". | Same problems as icp-py-core, plus a stale PyPI release. |
| Manual `cbor2` + shared `core/http.py` | Already implemented for the envelope. Still needed: hash-tree lookup (~40 lines) and verification. | Good. One HTTP stack, allowlisted, read-only by construction. |

SPEC says "Use icp-py-core if it works". It does install and support anonymous access,
but adopting it would weaken two guardrails that SPEC also requires. **Decision: manual
CBOR (`httpx` via `core/http.py` + `cbor2`).** We may borrow icp-py-core's certificate
verification as a reference implementation, without importing the package (see Open
questions).

## Sample response

No documented byte-level sample of a canister read_state response was found. The sample
below is **synthetic, built from
https://docs.internetcomputer.org/references/ic-interface-spec/https-interface/ and
https://docs.internetcomputer.org/references/certificates.cddl**, in CBOR diagnostic
notation. The hashes and the signature are placeholders.

```
# HTTP 200, body:
55799({ "certificate": h'd9d9f7a3...' })        # blob, itself tagged CBOR:

55799({
  "tree": [1,                                    # Fork
    [1,
      [2, h'63616e6973746572',                   # Labeled "canister"
        [2, <canister id bytes>,                 # Labeled <canister id>
          [1,
            [1,
              [2, h'636f6e74726f6c6c657273',     # Labeled "controllers"
                 [3, h'd9d9f7 81 4a <10-byte principal>']],   # Leaf: 55799([bytes])
              [2, h'6d65746164617461',           # Labeled "metadata"
                 [2, h'63616e6469643a73657276696365',
                    [3, h'73657276696365203a207b...']]]],     # Leaf: "service : {..."
            [2, h'6d6f64756c655f68617368',       # Labeled "module_hash"
               [3, h'<32 bytes sha256>']]]]],
      [4, h'<32-byte pruned hash>']],            # Pruned
    [2, h'74696d65', [3, h'<LEB128 ns>']]],      # Labeled "time" -> Leaf (always revealed)
  "signature": h'<48-byte BLS G1 signature>',
  "delegation": { "subnet_id": <subnet principal bytes>,
                  "certificate": h'<CBOR certificate from root subnet>' }
})
```

Hash tree CBOR tags (certificates.cddl): Empty `[0]`, Fork `[1, l, r]`, Labeled
`[2, label, t]`, Leaf `[3, bytes]`, Pruned `[4, hash]`. The certificate is
`tagged<{tree, signature, ? delegation}>`, and the delegation is `{subnet_id: bytes,
certificate: bytes}`.

Leaf decoding:
- `module_hash`: a raw 32-byte SHA-256. The path *does not exist* if the canister is empty
  (no module installed), so the lookup gives Absent. Record this as `module_hash = null`,
  not as an error.
- `controllers`: CBOR `#6.55799([* bytes .size (0..29)])`, an array of binary principals,
  which may be empty (a "blackholed" canister has no controllers, a key threat-intel
  signal). Convert each with `principal_to_text`.
- `metadata/candid:service`: raw custom-section bytes (UTF-8 Candid text). The path does
  not exist if the section is missing.
- Lookup results (certification spec): `Found v`, `Absent`, `Unknown` (pruned, cannot
  tell), `Error` (the path is an interior node, not a leaf).

Missing vs private metadata: a missing section gives `Absent` in a normal 200 response.
For a *private* section the anonymous sender is not authorized, and the spec says "If a
path cannot be requested, then the HTTP response to the read state request is undefined."
In practice the replica rejects the *whole* request with a 4xx, so this one path can
lose module_hash and controllers too. To prevent that, query `metadata/candid:service` in
its **own** read_state request, separate from `module_hash` + `controllers`, and treat a
4xx on that request as `candid = "private_or_unauthorized"`.

## Certificate verification

From the Certification page:
1. `root_hash = reconstruct(tree)`, where `reconstruct` hashes each node with SHA-256 and a
   domain separator. `domain_sep(s) = byte(|s|) . s`, with s = `ic-hashtree-empty`,
   `ic-hashtree-fork`, `ic-hashtree-labeled`, `ic-hashtree-leaf`. Pruned nodes contribute
   their hash directly.
2. `verify_bls_signature(key, signature, domain_sep("ic-state-root") . root_hash)`; the
   message prefix is `b"\x0dic-state-root"`. Ciphersuite
   `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`: a 48-byte G1 signature and a 96-byte G2
   public key.
3. Key: with no `delegation`, use the IC root key (DER, RFC 5480, algorithm OID
   1.3.6.1.4.1.44668.5.3.1.2.1). With a delegation, first verify the delegation
   certificate against the root key. It "must not itself again contain a delegation". Read
   the subnet key at `/subnet/<subnet_id>/public_key` (DER) and the scope at
   `canister_ranges` (the sharded `/canister_ranges/<subnet_id>/...` form or the
   legacy `/subnet/<subnet_id>/canister_ranges`). Check that the effective canister id is
   inside a range, then verify the outer certificate with that subnet key.
4. Freshness: look up `/time` (LEB128 nanoseconds, always revealed) and reject certificates
   older or newer than an allowed skew (agents use about 5 minutes).

Python BLS options: the `blst` supranational binding (SWIG, built from source; `icp-py-core`'s
optional `bls` extra and ic-py both depend on it) or `py_ecc` (pure Python, slow but
installable). Building blst by hand is a heavy dependency for the collector.

## How the collector will use it

1. Input: canister ids from seed IOCs / discoveries (texts checked by `principal_from_text`;
   the management canister `aaaaa-aa` is refused).
2. Request A: `read_state` on `/api/v3/canister/<id>/read_state` with paths
   `[canister,id,module_hash]` and `[canister,id,controllers]`. Request B: the same with
   `[canister,id,metadata,candid:service]`.
3. Store the raw response bytes in the raw store (cassette for tests) *before* parsing.
4. Parse: decode the certificate, look up each path, and decode the leaves as above. Record
   `cert_time` from `/time` and a verification status
   (`verified` / `unverified:<reason>`).
5. Emit observations: `module_hash` (hex), the controllers list (text principals,
   `[]` = immutable), candid text or `absent` / `private_or_unauthorized`.
6. All traffic goes through `IcClient.read_state` → `SafeHttpClient` (allowlist). There is
   no update, call or install path.

## Open questions

1. Verification scope for v1: full BLS verification needs `blst` (built by hand) or
   `py_ecc`. Conservative default: implement tree reconstruction plus the time check now,
   mark records `unverified:no_bls` until a BLS backend is chosen, and never trust
   unverified data for disclosure decisions.
2. The exact HTTP status for an unauthorized (private metadata) path is undefined in the
   spec. The fixture/recording step must capture it, and the collector should treat any
   4xx on request B as private or unauthorized.
3. The IC root public key value: embed it from DFINITY's published value (for example as
   used in agent-js) and pin it in a test. The value was not copied into this note.
4. Whether v2 read_state still answers on icp-api.io (it is deprecated). Plan for v3 only.

## URLs consulted

All accessed 2026-10-15.
- https://internetcomputer.org/docs/references/ic-interface-spec (301 to docs.internetcomputer.org)
- https://docs.internetcomputer.org/references/ic-interface-spec/
- https://docs.internetcomputer.org/references/ic-interface-spec/index.md
- https://docs.internetcomputer.org/references/ic-interface-spec/https-interface/
- https://docs.internetcomputer.org/references/ic-interface-spec/https-interface.md
- https://docs.internetcomputer.org/references/ic-interface-spec/certification.md
- https://docs.internetcomputer.org/references/certificates.cddl
- https://pypi.org/project/icp-py-core/
- https://github.com/eliezhao/icp-py-core
- https://raw.githubusercontent.com/eliezhao/icp-py-core/master/pyproject.toml
- https://pypi.org/project/ic-py/
- https://github.com/rocklabs-io/ic-py
- https://forum.dfinity.org/t/question-about-query-call-limits-to-icp-canisters-from-a-server/51457
- https://forum.dfinity.org/t/incident-handling-with-the-new-boundary-node-architecture/36390
