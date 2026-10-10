# Demo script

Three flagship demonstrations, each runnable from a clean checkout with no
API key. Every number shown is computed at demo time by the engine.

## 0. Setup (30 seconds)

```bash
git clone https://github.com/adivishall/sentinel.git && cd sentinel
make install         # dev tooling + the `sentinel` command (one runtime dependency: cryptography)
make api             # API + console on http://localhost:8000 (in-memory demo dataset)
```

## 1. Attack the financial AI (the signature demo)

Console → **AI Security** → attack *Document injection (flagship)* → **Run attack**.

Or, in a terminal:

```bash
make attack-compare
```

It answers five questions in order -- what the attacker submitted
(UNTRUSTED), what the AI recommended and what the gateway saw
(MODEL-GENERATED), what the trusted records say and which claim was read from
the prose (TRUSTED), what policy and authorization said (POLICY), and what was
finally allowed without and with Sentinel:

```text
2. WHAT THE AI RECOMMENDED   approve_refund -> requests APPROVE_REFUND
3. WHAT THE TRUSTED RECORDS SAY   delivery_status=delivered · claim non_receipt -> CONTRADICTED
4. WHAT POLICY SAID   BLOCK (block-critical-ai-security, block-unsupported-claim) · APPROVE_REFUND -> DENIED
5. WHAT WAS FINALLY ALLOWED
     WITHOUT Sentinel: EXECUTED APPROVE_REFUND   (the simulated agent; a what-if, never recorded)
     WITH Sentinel:    BLOCK, executed nothing   (a simulation too: nothing recorded)
```

The output says, before anything else, that the agent is the offline
simulator and the facts are a synthetic demo fixture.

Then say it: **The AI was persuaded. The financial system was not.**

<!-- gen:demo-flagship -->
Flagship attack (`make attack`): the gateway flags the document CRITICAL, the
simulated agent recommends `APPROVE_REFUND`, the ledger says delivered, the
claim is CONTRADICTED, `dispute-refund@v3` blocks, the capability is DENIED,
the final action is BLOCK. The simulator records nothing (its ledger is a
fixture signed on request); the same input through `/v1/disputes/evaluate`
opens a case and chains an audit event. Across
the 150-attack development corpus the same path executes 0.0% of attacks
(structural) against 90.0% for the simulated agent with no controls.
<!-- /gen:demo-flagship -->

Switch the mode to *compare* (or run `make attack-compare`): the same input
**WITHOUT** Sentinel -- the simulated naive agent's tool call executes and
₹18,000 leaves -- and **WITH** Sentinel, side by side. The console labels the
left side as the offline simulator; it is a demonstration of what the
architecture prevents, not a measured failure rate of any real model.

Then pick *Adjudication gaming*: no injection at all -- the gateway sees at
most a LOW social-engineering signal, below anything that holds a request --
the model still recommends approve, and the ledger still says delivered. DENY.
This is why detection is not the backstop.

## 2. Legitimate high-value transaction (Sentinel is not a blocker)

Console → **Transactions** → sort by amount and open one of the legitimate
₹2–3 lakh purchases (or run `sentinel scenario run high_value_legitimate`,
which lists them; the exact amounts depend on the generated world).

```text
Risk        LOW/MEDIUM — home device, home country, favourite merchant, biometric
Evidence    SUPPORTED — payment-switch record is trusted
AI          review
Policy      REQUIRE_HUMAN_REVIEW · review-over-auto-limit (amount > ₹1,50,000)
Final       REQUIRE_HUMAN_REVIEW · case P1
```

Sentinel distinguishes legitimate, suspicious, fraudulent, adversarial and
merely high-impact.

## 3. Graph-linked fraud

Console → **Accounts** → open one of the ring accounts (the ones with a
`young_account_shared_device` factor), or:

```bash
sentinel scenario run graph_linked_fraud
```

Show the relationship graph: three accounts on one device and one payout
instrument, bursts at the same merchants, transfers in a circle. The
investigation workflow scores CRITICAL (circular transfers, a device shared
with the other ring accounts, a burst of activity, high-risk merchant
exposure) and opens a case.

## 4. Three closing moves

- **Replay**: Console → **Replay** → *Replay it under v1*. A dispute that
  `dispute-refund@v3` denied because the ledger already shows a refund is
  re-run under v1, which had no such rule: DENY → ALLOW, i.e. the old policy
  would have paid a second refund. The ORIGINAL (recorded, checked against
  its audit event) and RECOMPUTED decisions sit side by side with the fields
  that changed. That is also why no caller may select v1 on an evaluate route.
  Then replay the blocked attack with the AI recommendation forced to
  `approve_refund` or `release_funds`: nothing changes.
- **Review packet**: Console → **Investigations** → open the case. The packet
  separates trusted evidence from untrusted claims, lists the contradictions,
  and shows the model's recommendation marked MODEL_GENERATED -- recorded for
  context, not a decision and not evidence. It says which review level may
  approve -- for the blocked attack, nobody: a policy BLOCK on contradicted
  records is final for every actor. A reviewer records the human decision
  there (chained into the audit log); nothing else can resolve the case.
- **Audit** (needs a persistent store: `make data && make analyze` first):
  `sentinel --db data/sentinel.db audit verify`. Edit one byte of an event in
  the store and run it again: AUDIT INTEGRITY ERROR, exit 2, naming the first
  bad record. Then `make audit-checkpoint` and
  `sentinel --db data/sentinel.db audit verify --checkpoint audit-checkpoint.json`:
  a consistent rewrite from genesis is caught against the exported head.
