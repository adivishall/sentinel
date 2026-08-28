# Demo video script — Sentinel (~90 seconds)

Record the browser at `console/index.html` (or the live GitHub Pages URL).
Screen-record with QuickTime (Cmd+Shift+5 on Mac). Talk over it or add captions.

---

## Shot list

**0:00–0:12 — The setup**  *(preset ① already selected, firewall ON)*
> "Banks now run LLM agents in the back office. This one triages disputes and
>  can issue refunds. Here's a cardholder submission for ₹2,40,000."
- On screen: read the dispute text. Point at the highlighted injection line.

**0:12–0:25 — Turn the firewall OFF**  *(click the toggle)*
> "Watch what happens with no protection. The agent reads the attacker's text…"
- Click **Run triage**. The right panel flips to **red: BREACH — ₹2,40,000 released**.
> "…and pays out ₹2.4 lakh that was never owed. One paragraph did that."
- Hold on the red BREACH box for 2 seconds.

**0:25–0:45 — Turn the firewall ON**  *(click the toggle back)*
> "Now with Sentinel." *(click Run triage)*
- Panel flips to **green: Denied**, the audit trail appears.
> "Layer 2 caught the injection and named the exact trigger. Layer 3 made the
>  real decision on the bank's verified facts — the attacker's text never
>  reached it. Layer 4 would have stopped the payout anyway."
- Slowly scroll the four-layer trail so each line is visible.

**0:45–1:05 — The hard case**  *(select preset ④ "Adjudication gaming")*
> "The clever attack has no injection at all — just an emotional story
>  engineered to fool the model."
- Firewall OFF → show it's a pure-narrative attempt. Firewall ON → **Denied**.
> "There's nothing to detect here, yet it's still blocked — because the decision
>  is made on facts, not on the story. That's the core idea."

**1:05–1:20 — It doesn't block real customers**  *(select preset ⑤ legitimate non-receipt)*
> "And a genuine dispute — an order that truly never arrived —"
- Firewall ON → **Refund approved (legitimate)**.
> "— is approved. Zero false positives. The firewall protects the bank without
>  punishing real customers."

**1:20–1:30 — The result**  *(cut to chart2_headline.png full screen)*
> "Across sixty attacks: two-thirds succeed unguarded, zero get through Sentinel,
>  and no legitimate refund is wrongly held. We defend the defender."

---

## Tips
- Record at 1280×800 or larger; the console is responsive.
- Do a silent dry run first so the toggle/click timing is smooth.
- If you narrate live, keep it calm — the visual does the work.
- Export ≤ 1080p, MP4. Put it in the GitHub README and/or link in the writeup.
