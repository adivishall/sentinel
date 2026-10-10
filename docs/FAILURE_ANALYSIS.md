# Failure analysis

Real defects found in Sentinel, how each was found, its root cause, the fix and
the regression test that fails if it comes back. Nothing here is hypothetical:
every entry names its fix commit and its test. Commit ids refer to the 2.3
pull-request branches (#21–#28 and their successor); merging them with merge
commits keeps these ids.

How defects were found: every 2.3 pull request was reviewed adversarially
before it was opened (a reviewer trying to break the change, not to read it),
the release candidate was audited from five perspectives (security, compliance,
hiring/README, operations, evaluation), and CI runs every suite on every push.

| # | Symptom | Root cause | Found by | Fix | Regression test |
|---|---|---|---|---|---|
| 1 | Request-body facts (`ledger`, `records`, `transaction`, `session`) executed authoritative refunds, onboardings and payments | trust labels came from the code path, not from what established the facts | trust audit | `2f3d151` | `test_policy_provenance.py::test_inv_prov_2_unverified_facts_never_execute_under_any_policy_version` |
| 2 | The multi-turn conversation route re-pointed a stored dispute with its own signed statement and new text; the refund executed with the account's risk dropped | the stored-record check ran on the narrative path only | review of #12 | `e207a93` | `test_fact_provenance.py::test_g1_the_conversation_route_does_not_re_point_a_stored_dispute_either` |
| 3 | The attack simulator recorded executed refunds on fabricated disputes | the simulator signed its preset ledger and ran on the recording runtime | review of #12 | `e207a93` | `test_evaluation_authority.py::test_the_simulator_never_records_and_scenarios_never_record_their_what_if_side` |
| 4 | Re-evaluating a record that had already executed recorded a second executed decision (a second refund) | nothing remembered that a capability had run for a subject | review of #11 | `05c4fd6` | `test_policy_provenance.py::test_re_evaluating_a_record_that_already_executed_does_not_execute_again`, `::test_two_concurrent_requests_execute_once` |
| 5 | A junior reviewer could undo an escalation and approve alone | escalation was reversible by the level below, and the four-eyes count did not restart | review of #13 | `c363715` | `test_reviewer_identity.py::test_r1_an_escalation_cannot_be_undone_by_the_level_below`, `::test_r2_an_escalation_by_transition_restarts_the_four_eyes_count` |
| 6 | A replay that overrode the policy kept the recorded release's `VERIFIED` stamp | a release was not bound to the exact document it signed | review of #14 | `ad54a36` | `test_policy_release.py::test_replay_reports_an_artifact_that_is_not_the_recorded_release` |
| 7 | DNS rebinding defeated the browser checks; two SIGHUPs deadlocked the server | the Host header was not checked; the reload ran inside the signal handler | review of #20 | `87d263e` | `test_secure_deploy.py::test_r1_dns_rebinding_is_refused_by_the_host_check`, `::test_r2_r3_reloads_happen_off_the_signal_handler_and_never_kill_the_server` |
| 8 | One corrupt record at checkpoint time disabled anchoring for good; the checkpoint job broke the running server | a checkpoint could be signed over a broken chain; records appended by another process were rejected | review of #17 | `b4d9893` | `test_audit_anchoring.py::test_r1_no_checkpoint_is_signed_over_a_broken_chain`, `::test_r2_a_checkpoint_job_in_another_process_does_not_break_the_server` |
| 9 | A benchmark row reported a 0% false-positive rate over zero measured controls | a rate was computed over an empty denominator | review of #16/#19 | `aa8ceb0` | `test_live_provider.py::test_r1_no_rate_over_nothing_and_a_partial_row_says_so` |
| 10 | `"DSP-000002\n"` with a body ledger opened a case on a dispute the system had already refunded; a human approval refunded it again | `^...$` with `re.match` accepts a final newline, so the id grammar and the held-record check missed it | review of #15 (by hand; the automated search could not reach it) | `b597307`, `08fd230` | `test_policy_provenance.py::test_r8_a_trailing_newline_is_not_a_new_subject`, `test_redteam.py::test_an_id_spelling_cannot_pay_a_refunded_dispute_twice` |
| 11 | The red team reported 22.4% / 25.8% detector evasion | it counted seeds the detector already missed unmutated, credited the last operator of a trail, and resent repeated variants | review of #15 | `af0d3de` | `test_redteam.py::test_detector_evasion_is_measured_against_an_unmutated_baseline`, `::test_no_query_repeats_a_variant_or_resends_the_seed` |
| 12 | Body records naming a stored merchant (or a case variant of its id) opened a case one reviewer could approve, onboarding it over its signed record once per spelling | merchants were not in the held-record check; the execution ledger compared keys case-sensitively | release audit (security) | `925ae6c` | `test_policy_provenance.py::test_r9_body_records_cannot_re_point_a_stored_merchant`, `::test_r10_one_subject_is_one_execution_whatever_the_case_of_its_id` |
| 13 | A repeat on an executed subject opened a review case that could never be approved | the composer checked "review" before "already executed" | release audit (security) | `925ae6c` | `test_policy_provenance.py::test_r11_a_repeat_on_an_executed_subject_is_a_denial_not_a_case` |
| 14 | The Docker image (and any non-editable install) could not start | the policy trust root was missing from `package-data`; CI only built the image | release audit (operations) | `34cd4b8` | `test_packaging.py::test_every_non_python_file_in_the_package_is_declared_as_package_data` |
| 15 | `audit verify --db <typo>` created a store, filled it with 5,000 synthetic transactions and printed "OK"; the documented policy-release runbook ended in REFUSED | the CLI seeded any empty store; the runbook omitted the operator's trust root and policy directory | release audit (operations) | `90b1447` | `test_ops_hardening.py::test_a_read_only_command_never_creates_or_seeds_a_store`, `test_policy_runbook.py::test_an_operator_can_release_the_policies_under_their_own_root` |
| 16 | CI failed intermittently on `test_a_human_approval_is_an_execution_too` | the test signed one record twice with the same sequence; a second boundary between the two made them equivocation (`INVALID`) | CI | `2f97abf` | the test itself (it now evaluates one statement twice) |

## Patterns

- **Every bypass was in a structured channel, none in text.** Text reaches the
  claim type and the detector's rating; the facts that decide come from signed
  statements or the store. The defects were in the paths that name or carry
  facts: routes (2, 12), id grammar (10), what-if and simulation runtimes (3),
  the execution ledger (4, 12).
- **The automated search found the cosmetic defects; people found the bypasses.**
  The red team's zero bypasses are structural (#11); the newline double refund
  (#10) and the merchant re-pointing (#12) were found by reading the code
  against its invariants.
- **Measurements overstated before they understated.** #9 and #11 were numbers
  that looked better than the data supported; both now carry their denominator.

## What would show a regression

`make test` runs every test named above. `docs/INVARIANTS.md` maps each
security invariant to the tests that fail if it breaks, and
`tests/test_invariant_table.py` fails if a named test disappears.
