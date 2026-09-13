# Image notes

Two square-ish (4:5, 1080x1350) figures, shared visual system: the SENTINEL
wordmark, DejaVu Sans typography, and one restrained palette (ink text on
off-white, terracotta = untrusted, blue = trusted, gold = the L3 backstop, green
= final decision). No stock art, no neon, no hacker imagery. Designed to read on a
phone: large type, generous whitespace, no dense tables.

## Image 1 — `sentinel-architecture.png` (post first)

**What it communicates:** the whole idea in one figure. A vertical pipeline runs
UNTRUSTED input through L1 provenance, L2 injection detection, and the LLM agent,
then crosses a clearly drawn TRUST BOUNDARY ("attacker prose stops here") into the
TRUSTED zone, where L3 decides on verified facts, L4 applies capability policy, and
a final decision plus audit trail comes out.

**Why this design:** the single most important point is the trust boundary, so it
is the visual centerpiece: the untrusted layers sit in a red-tinted zone, the
trusted layers in a blue-tinted zone, with rotated UNTRUSTED / TRUSTED labels down
the side and a dashed divider between them. L3 is highlighted in gold because it is
the architectural backstop. A recruiter grasps "input is untrusted, the decision is
made on trusted facts" in a few seconds; an engineer sees exactly where the
boundary is enforced.

## Image 2 — `sentinel-results.png` (post second)

**What it communicates:** the evidence. The headline is 83.3% to 0.0% attack
success (no firewall vs Sentinel) as two large cards, with the benchmark scope
underneath (60 attacks, 6 classes, 18 legitimate controls, 0.0% false positives)
and a held-out badge (0.0% / 0.0% on unseen wording). A small three-bar ablation
(no firewall 83.3%, detection only 6.7%, full firewall 0.0%) shows that detection
alone still leaks adjudication-gaming attacks and that L3 closes the gap.

**Why this design:** the before/after must land in two to three seconds, so it is
the biggest element on the image. The ablation is included because it is the honest
core of the result (it shows *which* layer does the work), but kept to three bars
so it stays readable. All numbers are benchmark-scoped wording ("on the evaluated
benchmark", "held-out set"), never a universal-security claim.

## Regenerating

Both images are produced by `social/linkedin/make_images.py` (matplotlib, no stock
assets). Run `python3 social/linkedin/make_images.py` from the repo root to
regenerate them. The headline numbers in the figures match `eval/results/` (verified
manually against `summary.json`, `ablation.json`, `heldout.json`).
