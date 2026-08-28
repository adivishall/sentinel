# Sentinel — an AI firewall for the bank's own AI

**Mastercard Innovation Challenge @ GFF 2026 · AI Defence Lab for Payment Security**

Banks now run LLMs deep in the back office: dispute triage, KYC/KYB review, AML
narration, merchant onboarding. Those pipelines ingest **attacker-controlled text
and documents through entirely legitimate channels** — a chargeback narrative, an
uploaded invoice, a merchant's own website copy. A single crafted paragraph can
talk a triage agent into refunding money that was never owed, or an onboarding
agent into approving a shell merchant.

Everyone is defending against fraud *committed with* AI. **Almost nobody is
defending the bank's own AI from being the thing that's attacked.** Sentinel does
that: a four-layer firewall that sits between untrusted input and a financial LLM
agent's irreversible actions.

## The result (offline, deterministic)

| Metric | Value |
|---|---|
| Attack success — **no firewall** | **83.3%** |
| Attack success — **with Sentinel** | **0.0%** |
| False positives on legitimate refunds | **0.0%** |

Run it yourself: `make offline` (no API key needed).

## The four layers

1. **Provenance tagging** — every untrusted span is delimited and labelled as
   *data, never instruction*. (`firewall/provenance.py`)
2. **Injection detection** — untrusted spans are scored for override / authority-
   spoof / rule-forgery signatures; every block names its trigger. (`firewall/detect.py`)
3. **Structured-facts adjudication** ★ — the real decision is made by a second
   adjudicator that sees **only verified facts from the bank's own records**, never
   the attacker's prose. This is structurally immune to text-level attacks,
   including "adjudication gaming" narratives that contain no injection at all.
   (`firewall/adjudicate.py`)
4. **Capability limits** — irreversible, high-value effects are hard-gated to a
   human regardless of what the model decided. (`firewall/limits.py`)

## The attack taxonomy (`red/taxonomy.py`)

Direct injection · Authority spoofing · Document-borne injection · Rule-citation
forgery · Multi-turn escalation · **Adjudication gaming** (the honest hard case:
a narrative engineered to exploit the model's heuristics with no injection to detect).

## Run it

```bash
make offline     # full pipeline, no API key: corpus -> eval -> charts
make demo        # open the interactive console
```

Live mode (real Claude agents + adjudicator):

```bash
cp .env.example .env   # add ANTHROPIC_API_KEY
export ANTHROPIC_API_KEY=sk-ant-...
make all
```

Both modes exercise the **same firewall code**. Only the agent's reasoning differs:
offline it is a faithful deterministic model of the documented failure mode (an LLM
that treats all in-context text as instructional); live it is a real Claude agent.

## Layout

```
llm.py              dual-mode client (live Claude | deterministic offline)
agents/             the VICTIMS: dispute_triage, kyb_review, tools
red/                taxonomy + corpus (60 attacks, 18 legitimate controls)
firewall/           the four layers + pipeline (the contribution)
eval/               harness + charts -> eval/results/
console/index.html  standalone demo (the 90-second video)
docs/               ARCHITECTURE.md, LIMITATIONS.md
```

## Honesty notes

See `docs/LIMITATIONS.md`. In brief: the offline agent is a simulation, the
corpus is synthetic and partly templated, and *adjudication gaming* is where the
offline agent looks strongest (a rule-based agent resists emotional narrative) —
which is exactly why layer 3 exists for the live case.
