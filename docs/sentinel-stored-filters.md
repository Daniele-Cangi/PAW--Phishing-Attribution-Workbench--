# Stored country/score filters and statistics

This contract covers four existing `CampaignDatabase` reader methods: country and
score selection, stored-row statistics and explicitly unavailable attacker
correlation. It adds no collector, classifier, writer/schema, command or UI.
Use `read_only=True` for passive source admission. Other listing/worker selectors
retain their existing limits and contract; these methods use the complete forensic
reader without a latest-100 cap.

## List selectors

`get_victims_by_country` requires a nonblank string and selects exact original
country strings from unambiguously decoded geographic JSON objects. No case,
whitespace or country-name normalization is applied. Malformed/ambiguous JSON,
non-finite JSON, invalid encoding, arrays/scalars and non-string countries do not
match. They cannot suppress a valid neighboring row through SQL `json_extract`
failure or first-key interpretation. Valid decoded BLOB JSON retains its typed
original storage. A comma in a country label remains part of that literal label.

`get_victims_by_risk_score` is a legacy name for a finite stored-number predicate,
not a risk verdict. The threshold must be finite numeric and non-boolean; finite
negative and arbitrarily large integer thresholds are accepted. Only finite
stored numeric scores >= the threshold match. Missing, nonnumeric or non-finite
scores do not match; SQLite text-vs-number type ranking is not a numeric comparison.
Stored values are not coerced. SQLite column affinity may already have converted
input to another type; the reader describes actual returned storage values.
Ordering is score descending, with stable ties in `click_time DESC, id DESC` order.
Country selection retains that complete-reader order.

Both methods retain their list return shape and complete matched reader records,
including JSON evidence. These are deliberate predicates; an empty list means no
stored rows match, not absence of geographic/hostile activity. Use
`get_forensic_victim_intelligence` for the complete unfiltered inventory and JSON
decoding outcomes. Reader/storage errors propagate. Lists retain other raw native
scalars (including BLOB values), as the general Python reader does; they are not
JSON publishers and may require an explicit unsupported-storage decision by a
serializing caller. Native values are not stringified or redacted here.

## Statistics and unsupported interpretation

`get_victim_statistics` returns a version-1 description of all selected stored
rows with complete `source_records`. The compatibility `total_victims` counts
stored rows, not people. `status_breakdown` counts original string labels,
including empty strings, with source IDs and separate unusable-status IDs. It
does not authenticate analysis completion. `risk_distribution` uses string keys
for finite positive stored numbers with exact source IDs; unusable scores and
nonpositive scores have separate IDs. It does not calibrate risk.

The report follows the strict JSON-compatible source boundary: unsupported native
scalars and non-finite source numbers fail explicitly before returning a partial
report. Typed malformed JSON remains retained. Missing/corrupt/incomplete storage
and unsupported WAL/pending journals cannot become healthy empty statistics.
Healthy empty storage can return zero stored-row counts. No output files or
directories are created by these readers.

`recent_victims_24h` is `None` with an explicit unavailable reason. The previous
SQL lexical comparison counted `not-a-date` as recent; timestamp interpretation
has no validated contract here. Original `click_time` values remain available.
Risk and identity interpretations are explicitly unavailable as well.

`get_attacker_correlations` raises an explicit unavailability error before reading
storage, including on empty sources. The prior IPv4 string-prefix groups, comma
splitting and average score do not establish network membership or attacker
infrastructure; an empty success list would hide that unavailability. Complete
stored IPs, geographic observations and correlation labels remain in the forensic
reader and statistical sources. The separate active IP analyzer/classifier and
correlation updater are not validated or changed by this passive boundary.

## Verification and remaining work

`test_sentinel_stored_filters.py` exercises real SQLite neighbors, ambiguous JSON,
literal labels, numeric boundaries/sorting, legacy layouts, preserved JSON files,
source failures and unavailability before I/O. `integration_sentinel_stored_filters_real.py`
checks 12 cold API processes, complete 213-row sources, matched-list source
equality, actual JSON and unchanged storage trees under the Python offline guard.
Older tests that expected the now-corrected SQL JSON failure instead assert no
match for unusable geography; positive-neighbor tests establish retained coverage.

Fixtures establish execution and source fidelity, not real-world risk, identity,
timestamp authenticity or OS isolation. No live endpoint is accessed. Stored-data
resource limits, general non-JSON publication, atomic concurrent-writer snapshots,
worker/lifecycle/listing dispositions remain open S11 work. External operational
entry points remain S12, active verification S14 and the application UI S16.
