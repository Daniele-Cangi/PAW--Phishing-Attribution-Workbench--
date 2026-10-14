# Legacy interaction diagnostic

This is an optional diagnostic for existing saved data. Its present role is
passive inspection; future collection, behavioral investigation or cross-case
extensions require a separate investigative need and validation plan. They are
deferred while PAW's email-analysis engine is stabilized.

`python /path/to/checkout/check_victims.py` reads the configured existing Sentinel
database relative to the current working directory and prints the existing
`CampaignDatabase.get_victim_statistics()` report as JSON. Normal project
dependencies are required. The script does not change the working directory,
initialize/migrate storage, import a network collector or run analysis.

Previously the script changed into a personal Windows directory at import time,
constructed the default writable database, read a latest-100 preview and printed
its length as a total. It looked up nonexistent `ip_address`, `user_agent` and
`timestamp` keys, substituting `N/A` for available `victim_ip`, `victim_ua` and
`click_time` sources. Its five displayed rows were a slice of that preview.

The diagnostic now runs only under its main guard or an explicit `main()` call.
Help and invalid arguments are handled before Sentinel/configuration access.
Accepted execution uses the existing read-only storage admission and complete
statistics reader. Output intentionally changes from a five-row text preview to
the full existing report, including all source records, typed original JSON
storage/decoding evidence, literal counts and unavailable interpretation reasons.
Missing or corrupt storage/configuration, incomplete schema, WAL/pending journals
and unsupported native JSON values fail nonzero without a partial report. A
healthy empty database instead yields a successful report with zero rows.

Legacy report keys such as `total_victims` are compatibility names. The report's
`evidence_scope`, `count_scope` and `unavailable` fields explain that counts refer
to stored rows, not people or authenticated visits; identity, calibrated risk and
recent-event interpretation are unavailable. Stored timestamps remain unverified
source strings, user agents are retained completely and absent values remain NULL.

`tests/integration_legacy_interaction_check_real.py` executes 18 actual processes:
17 cold diagnostic/argument/import paths under the Python no-egress guard and one
direct script execution outside the checkout without host `PYTHONPATH`. Actual
saved/default/configured/empty/legacy and error sources remain byte for byte
unchanged. Two 210-row fixtures verify complete source ordering beyond the old
100-row cap, actual IP/UA/time fields, NULLs, duplicate-key JSON and invalid UTF-8
TEXT provenance. JSON output equals the existing full statistics API report.
Malformed native scalars fail without stdout data. Help/invalid options/import
preserve a malformed configuration without importing Sentinel. No CLI bootstrap,
collector imports, new threads or blocked operations occur in guarded processes.

This dispositions one S12 script. Package readers/writers and the report schema
are unchanged. Existing complete-reader resource limits, concurrent-writer
snapshot guarantees and broader configuration/link admission remain open; the
Python guard is not OS isolation. No classifier accuracy, identity, authenticity
or new attribution capability follows from this diagnostic.
