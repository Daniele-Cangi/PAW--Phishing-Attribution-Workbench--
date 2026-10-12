# Stored interaction statistics and candidate labels

This contract covers only `IntelligenceAnalyzer.get_interaction_statistics` and
`get_potential_attacker_interactions`, with their shared private source/numeric
helpers. No CLI, GUI, collector, classifier or writer capability is added.
The default writable analyzer constructor and active interaction classification
remain outside this contract. Use `read_only=True` for passive saved-source reads.

Both methods select complete sources through the existing forensic-row reader:
`None` selects all, while string case identifiers (including empty strings) use
exact bound SQL. Older cases are not filtered from a latest-100 preview. Missing,
corrupt, incomplete, WAL or pending-journal storage propagates errors, including
later admission checks. Unsupported selected native JSON scalars/non-finite
numbers cause explicit serialization errors rather than lossy stringification or
silent omission. Unrelated cases do not cross a case selection boundary. Healthy
empty selections return empty observations, distinct from source failure.

## Statistics

The version-1 report retains every selected row in `source_records`, including
typed original JSON storage and decoding outcomes. `interaction_types` counts
literal nonblank string labels, with source IDs and unusable-label IDs.
`classified_interactions` is a compatibility name for rows with nonblank stored
labels other than literal `unknown`; it does not attest classification. Labels
are not stripped/normalized, so `unknown ` remains distinct. SQL NULL and blank
labels are not classified. Legacy absent-column defaults retain the existing
reader contract; no migration or new inferred label is introduced here.

Stored confidence is usable only as a non-boolean numeric value in 0..1. Numeric
and unusable source IDs are listed. `stored_candidate_score_at_least_0_7` counts
literal `attacker_test`/`potential_attacker` labels with usable stored score >=0.7;
`stored_suspicious_label_rows` counts literal `automated_or_suspicious`/
`suspicious_ip` labels. Both have exact counted IDs and unverified scope. They
do not establish attacker identity, malicious behavior or calibrated confidence.
Original scores/labels and malformed indicator sources remain available.

Legacy `high_confidence_attacker_interactions` and `suspicious_interactions` are
`None`, and `potential_attacker_ips` is empty with explicit unavailable reasons.
Descriptive replacement counts above remain usable; unavailable interpretations
must not be read as verified zero risk or absence of attackers. Counts describe
stored rows, not unique persons, authenticated events or independently observed
visits. Report construction/statistics create no output files or directories.

## Candidate selector compatibility

`get_potential_attacker_interactions` retains its legacy list return type. Its
name does not attest attackers. It selects the four literal labels listed above
with usable stored numeric score >= the supplied finite 0..1 threshold (default
0.6). Zero is still a numeric threshold and **does not** admit absent/NULL/unusable
scores; this differs from the geographic report's disabled-filter zero option.
Invalid thresholds fail before source reading. Empty results mean no rows match
this stored-label/score predicate, not absence of actual malicious activity.

Results retain existing field aliases and add complete `source_record`, including
metadata/user-agent/JSON decoding evidence, unverified scope, selection criteria
and explicit unavailable identity/risk. Indicator/geolocation aliases may carry
reader fallbacks; inspect their original sources and decoding status before using
them. The alias `risk_score` is an uncalibrated stored value. Sorting uses stored
score descending with stable ties in reader order (`click_time DESC, id DESC`).
This selector intentionally returns matches; use statistics `source_records` for
the complete selected inventory and unusable-score/label IDs.

## Verification and remaining boundaries

`test_sentinel_interaction_statistics.py` exercises actual complete SQLite rows,
literal cases, NULL/blank labels, score boundaries/stable sorting, retained JSON
sources, legacy layouts, unsupported scalars, empty data and journal failures.
`integration_sentinel_interaction_real.py` checks 14 cold actual API processes,
saved JSON source equality and unchanged original storage trees under the Python
offline guard. These fixtures establish execution and source fidelity, not
accuracy, identity, authenticity or OS isolation. No live endpoint is used.

Other statistical SQL consumers and lifecycle/active-classification paths remain
open S11 work, alongside general non-JSON storage/resource limits and concurrent
writer snapshot guarantees. External operational entry points remain S12, active
network verification S14 and application UI S16. This focused correction does not
close those families or calibrate the existing classifier.
