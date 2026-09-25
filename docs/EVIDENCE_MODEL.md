# Evidence model

Rendered by `make docs` from `sentinel/domain/enums.py`,
`sentinel/domain/evidence.py`, `sentinel/security/trust_boundary.py`,
`sentinel/evidence/contradiction.py` and `sentinel/evidence/reconcile.py`.

## Evidence objects

Every fact the decision sees is an `Evidence` object: an id, a kind, a
source, a trust class, a field, a value, a status and a content hash. Two
constructors exist and the type enforces the boundary: `Evidence.fact` is
VERIFIED and accepts only `TRUSTED_INTERNAL`, `VERIFIED_EXTERNAL`; `Evidence.claim` is CLAIMED and refuses a
trusted class. A `MODEL_GENERATED` value can therefore never become VERIFIED
evidence by any code path, and a fabricated "ledger extract" pasted into a
narrative arrives as a claim, whatever it says (the `synthetic_evidence`
threat class).

| EvidenceKind | Typical source |
|---|---|
| `ledger_fact` | the institution's payment ledger (`DisputeFacts`) |
| `acquirer_record` | verified acquirer records (`KYBFacts`) |
| `session_record` | authentication service |
| `risk_signal` | the risk or monitoring engine (a trusted computation over records) |
| `user_claim` | cardholder prose |
| `merchant_claim` | merchant application copy |
| `document_claim` | an uploaded document |

| EvidenceStatus | Meaning |
|---|---|
| `VERIFIED` | from a trusted source; the only status that can support a claim |
| `CLAIMED` | asserted by an untrusted party; unverified |
| `CONTRADICTED` | a claim the trusted record disagrees with |

## Claims

Untrusted text is opaque. The only value ever derived from prose is a coarse
`ClaimType` (a small ordered set of regexes in `UntrustedText.classify`; a
clear "never arrived" wins over a tracking mention). The claim type is a
**selector** for which trusted field to check -- never evidence. `Claim`
carries the type, the source, the trust class and a hash of the text; the
text itself is not stored on the decision or in the audit chain.

| ClaimType | Checked against | Values that support it |
|---|---|---|
| `non_receipt` | `delivery_status` | `not_delivered`, `returned`, `lost` |
| `in_transit` | — | never supported: held for a human (premature dispute) unless the ledger says delivered, which contradicts it |
| `duplicate` | `duplicate_confirmed` | `True` |
| `cancellation` | `cancellation_confirmed` | `True` |
| `unauthorized` | `cardholder_present` | `False` |
| `unspecified` | — | never supported (nothing recognisable to verify) |

`DisputeFacts.supports(claim)` is a pure function of the facts: the claim
only chooses which field to read.

## Trusted facts

`TrustedFacts` subclasses are built from records only (`from_ledger`,
`from_records`), and each constructor reads its declared fields by name: any
other key on the mapping (a `narrative`, `document` or `note`) is never
copied (`tests/test_trust_boundary.py`). Every field renders itself as
VERIFIED evidence.

| `DisputeFacts` field | Default | Values |
|---|---|---|
| `amount` | 0 |  |
| `merchant` | 'unknown' |  |
| `delivery_status` | 'unknown' | delivered \| not_delivered \| in_transit \| returned \| lost |
| `prior_disputes_90d` | 0 |  |
| `policy_auto_limit` | 50000 |  |
| `duplicate_confirmed` | False |  |
| `cancellation_confirmed` | False |  |
| `cardholder_present` | True |  |
| `refund_state` | 'none' | none \| pending \| refunded |
| `transaction_status` | 'settled' | settled \| pending \| reversed |
| `merchant_response` | 'none' | none \| accepted \| contested |
| `auth_strength` | 'unknown' | none \| password \| otp \| biometric |
| `customer_tenure_days` | 0 |  |

| `KYBFacts` field | Default |
|---|---|
| `registration_status` | 'unverified' |
| `domain_age_days` | 0 |
| `business_age_days` | 0 |
| `prior_flags` | 0 |
| `mcc_risk` | 'unknown' |

## Contradictions

A contradiction is a claim and a verified fact on the same field that cannot
both be true. Compatibility is data: for each field, which claimed values are
consistent with which recorded values; a field with no table falls back to
strict equality. An absence of confirmation (`duplicate_confirmed = False`)
is *not* a contradiction -- it leaves the claim UNSUPPORTED, not CONTRADICTED.

| Field | Claimed value | Recorded values consistent with it |
|---|---|---|
| `delivery_status` | `never_received` | `in_transit`, `lost`, `not_delivered`, `returned` |
| `delivery_status` | `in_transit` | `in_transit`, `not_delivered` |
| `delivery_status` | `delivered` | `delivered` |
| `duplicate_confirmed` | `True` | `False`, `True` |
| `duplicate_confirmed` | `False` | `False`, `True` |
| `cancellation_confirmed` | `True` | `False`, `True` |
| `cancellation_confirmed` | `False` | `False`, `True` |
| `cardholder_present` | `False` | `False` |
| `cardholder_present` | `True` | `False`, `True` |
| `registration_status` | `verified` | `verified` |

Each contradiction is a first-class object (`claim_evidence_id`,
`fact_evidence_id`, `field`, `claimed`, `recorded`, `impact`) shown in the
console, the case packet and the decision.

## Reconciliation verdicts

| EvidenceVerdict | Meaning | Consequence in the composer |
|---|---|---|
| `SUPPORTED` | the trusted records support the claim | the only verdict under which a consequential capability can execute |
| `UNSUPPORTED` | no trusted record confirms the claim | DENY |
| `CONTRADICTED` | a trusted record says the opposite | DENY, with a `Contradiction` object attached |
| `INSUFFICIENT` | the claim cannot be mapped to a trusted fact yet | REQUIRE_HUMAN_REVIEW (fail-safe) |

**Dispute** (`reconcile_dispute`): an UNSPECIFIED claim is UNSUPPORTED (nothing
recognisable to verify); IN_TRANSIT is CONTRADICTED when the ledger says
delivered and INSUFFICIENT otherwise (a premature dispute, held for a human);
any other claim is SUPPORTED when `supports()` holds, CONTRADICTED when the
contradiction engine found a conflict on the claim's field, and UNSUPPORTED
otherwise. Document claims are reconciled alongside the narrative's claim.

**Merchant onboarding** (`reconcile_kyb`): the applicant implicitly claims to
be a verified, clean business. Shell registration or ≥ 2 prior flags →
CONTRADICTED; verified with domain ≥ 30 days, business ≥ 90 days and no flags
→ SUPPORTED; anything else → INSUFFICIENT (human review). The application
text and document can add claims and contradictions; they cannot add facts.

**Records-only workflows** (transaction authorisation, account security,
investigations): the evidence is the trusted records themselves and the
verdict is SUPPORTED; policy and the registry carry the decision.

## The model's recommendation is not evidence

The agent's tool call is interpreted into an `AIRecommendation`
(`MODEL_GENERATED`) and recorded on the `Decision` as `ai_recommendation`, for
explainability and measurement. It is never added to an `EvidenceSet`, never
reconciled and never read by the composer's trusted view; an `Evidence` item
with `MODEL_GENERATED` trust cannot be VERIFIED even if one is built by hand.
`tests/test_model_output_separation.py` and `tests/test_evidence.py` pin this.
