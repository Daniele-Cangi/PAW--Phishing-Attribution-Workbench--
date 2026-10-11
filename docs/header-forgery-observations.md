# Passive header descriptions and unavailable forgery assessment

This focused S09 correction concerns `paw/core/header_forgery.py`. It does not
introduce a new header detector, authentication verifier or collection flow.

## Reproduced failures and supported consumers

On merged PR43 (`c6d6991`), the helper interpreted arbitrary hop keys containing
`spf`, `dkim` or `dmarc` and values containing `fail` or `none` as authentication
failures. Incidental text such as "this is not a failure" and "none of these
are results" yielded three failures and an aggregate forgery score of three.
Backward timestamp claims plus three syntax flags yielded score five and "high"
confidence. Empty input yielded score zero and "low" confidence. An IP/FQDN
check skipped under no-egress still left `ip_fqdn_mismatch: false` in the output.
The legacy helper also contained a permitted-network DNS path comparing a claimed
IP with current IPv4 answers; that path was inspected, not run against a domain.
Such answers would not establish a historical Received binding or forgery.

The tracked production consumer is `trace.run_case`: normalized `ordered_hops`
go to `analyze_received_anomalies`, which writes `received_anomalies.json`.
`received_score_components` supplies three descriptive components, all zero, to
the existing scorer. The separate aggregate entry point
`analyze_header_forgery_indicators` has no identified production caller in the
tracked Python sources. It must not be described as a full-analysis verifier.

## Preserved information and changed interpretation

The passive helper still retains selected IP categories with header indexes,
receiver-boundary uncertainty, timestamp observations, adjacent comparisons,
repeated-address claims, non-monotonicity when supported, and the count of supplied
`fqdn_ok: false` flags. These observations are unverified descriptions. Counted
syntax flags do not establish a malicious host, invalid routing or authenticity.
An incomplete timing chain cannot establish whole-chain monotonicity.

The pipeline's existing `received_path.json` retains normalized source records,
original Received strings and indexes; original `input.eml` and parsed header
evidence retain the email's authentication claims. This correction does not
mutate or remove those inputs or introduce a replacement header inventory.
The normalized-hop dictionary contract is the supported passive input; raw
Received strings, arbitrary object shapes and standalone size admission are not
newly supported by `analyze_received_anomalies`. Existing ingress supervision
and Received parsing limits remain separate upstream contracts.

`forgery_assessment` now explicitly reports `status: unavailable` and
`verified: false`, including for an empty chain. Unchecked `ip_fqdn_mismatch`
and `missing_auth_headers` become null, rather than false. Existing empty
`auth_failures` and `spoofing_patterns` arrays mean no independently verified
findings are produced by this helper; they must not be read as proof of successful
authentication or absence of spoofing. The substring authentication heuristic,
current-DNS comparison and unused private-IP helper are removed. Authentication
evidence and network collectors elsewhere in PAW are unchanged.

The aggregate function name/signature and legacy output keys remain callable.
It does not interpret input: `status: unavailable`, `verified: false`,
`forgery_score: null`, `confidence: null`, `indicators: []` and an explicit reason.
Consumers must handle unavailable assessment rather than infer a low forgery risk
or treat timestamps/syntax as a calibrated detector. Passive information remains
available through the active Received description path; no new aggregate consumer
or substitute scoring algorithm is added.

## Verification scope and remaining boundaries

Focused contracts cover missing data, incidental and explicit authentication
words, untouched source records, backward/syntax descriptions, IPv4/IPv6 claims,
unavailable aggregate results and unchanged zero score components. Static source
checks establish removal of this helper's direct networking path; actual calls
under offline policy check that no blocked operation is attempted. These are
regression inputs and source checks, not independently labeled phishing examples
or evidence of classifier accuracy.

The existing actual full CLI timing integration exercises fourteen EML cases,
source order/indexes and original bytes, persisted descriptions, neutral scoring
and valid evidence seals. It is run before the correction and extended to verify
the new unavailable fields afterward. The private audit records exact versions,
source differences and results; general tests and the actual rebuilt wheel check
the supported local regression/package scope.

On local Windows/Python 3.13, nine focused contracts pass; the general suite
passes 620 of 628 tests with eight platform exclusions. The actual full CLI
integration passes all fourteen cases before and after the correction. The
existing CLI/HTTP integration also passes using repeated original EML bytes,
explicit no-egress and loopback HTTP: shared ownership and blocked active readers,
unchanged query/index state, stopped-case verification/ZIP export, and supervisor
crash recovery with worker shutdown before partial sealing. The rebuilt wheel's
metadata/entry points and all 90 current Python-source bytes match. This is not
a new clean dependency installation, private 20-message corpus replay or an
independently labeled accuracy evaluation.

No authenticated SMTP peer observation, independent SPF/DMARC/ARC result,
receiver trust boundary, historical IP/host ownership, controlled detonation or
forgery verdict is established here. Python no-egress remains an application
guard, not OS isolation. No sample URL, domain resolution, attachment execution
or Docker is needed for this audit. UI and controlled egress remain later stages;
the remaining S00-S16 register is not declared complete.
