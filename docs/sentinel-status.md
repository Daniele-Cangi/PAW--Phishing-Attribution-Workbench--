# Passive Sentinel status and stored counts

This S11 correction follows merged PR47 (`dac0bd3`). Actual SQLite storage
reproduced two statistics errors: `total_campaigns` counted only active campaigns,
and `unacknowledged_alerts` was always zero. Actual CLI `monitor status` in a
directory without storage created `sentinel.db` and printed `Running: False`
from a new, unstarted monitor instance. That flag did not establish whether
another process was monitoring campaigns.

## Contract

`CampaignDatabase.get_monitor_statistics()` returns existing integer keys:

| Field | Stored row criterion |
| --- | --- |
| `total_campaigns` | All campaign rows, including removed/inactive/NULL-status rows. |
| `active_campaigns` | Campaign rows whose stored status equals `active`. |
| `unacknowledged_alerts` | All alert rows whose stored acknowledgement equals zero, including older alerts. |

These are stored counts, not authenticated campaign assessments or proof of
service activity. NULL/other acknowledgement values are not silently classified
as unacknowledged. There is no last-24-hours window or timezone interpretation;
the previous unused cutoff and zero placeholder are removed. Alert rows are
counted regardless of campaign association; this does not validate foreign keys.
One aggregate SELECT obtains all three counts under one SQLite statement's read
snapshot, without loading or decoding metadata/messages. Damaged JSON therefore
does not abort these counts, but successful counting does not certify its validity
or the health of every table. Missing required tables/columns raise an error
instead of becoming zero counts. Writers, schema/migrations, scoring and the
existing active-only list readers are unchanged.

`SentinelMonitor.get_stats()` uses these actual counts. Its existing `is_running`
boolean remains the current object's requested-running flag and now explicitly
carries `is_running_scope: this_instance_flag`. It is not a thread-liveness test,
cross-process service detector or persistent lifecycle guarantee. Its default
constructor still initializes writable storage for writer consumers; a caller
wanting passive admission must supply a read-only database explicitly.

The CLI `paw monitor status` now shares the [passive admission](sentinel-passive-opening.md)
path with `monitor list`, using the configured database path. It constructs
neither a monitor nor a collector, loads no monitoring/intelligence modules and
starts no thread or executor. It displays the three stored counts and
`Running: unknown (not observed by this command)`. It does not infer running or
stopped from the existence of rows, a local flag, configuration or recent checks.
Missing, damaged, incomplete or unsupported storage exits nonzero before printing
a success status or zero-count summary. Existing empty required tables
legitimately return zero. No database/configuration creation, migration,
checkpoint or journal recovery is performed.

## Verification and remaining boundaries

Five new actual SQLite contracts cover all campaign states, old/recent and
acknowledged/NULL-acknowledgement alerts, malformed metadata independent of counts,
updates and repeated passive reads, legitimate zero counts, missing tables/columns,
explicit instance-flag scope and later journal admission. Database bytes remain
unchanged after readers. The previous 28 Sentinel contracts remain in place.

An actual ten-case CLI integration checks populated and empty tables, legacy
storage without the interaction table, default/configured missing paths, corrupt
and zero-byte files, missing alert storage, WAL mode and pending journals. Names
and bytes remain unchanged on success and rejection, including configuration and
a filename with URI special characters. After common CLI dependency bootstrap,
guarded offline dispatch records zero blocked operations and imports no Sentinel
monitoring/enrichment modules. This is not a cold-start or OS-isolation guarantee.

On local Windows/Python 3.13, all 33 Sentinel contracts pass and the complete
serial suite passes 653 of 661 tests with eight platform exclusions. The previous
seven-case actual passive CLI list and original-EML CLI/HTTP no-egress regression
also pass, including stopped-case exports and supervisor-crash recovery. A real
rebuilt wheel matches metadata/entry points and all 90 package Python sources.
These checks do not prove clean dependency installation or attribution accuracy.

Read-only admission still requires saved rollback-journal storage without WAL or
pending sidecars; it does not freeze external writers or produce a forensic
filesystem snapshot. SQL JSON filter admission, arbitrary database/output budgets,
report/export provenance, other statistical consumers and start/stop lifecycle
remain open S11 work. Active monitoring/controlled egress is S14; UI is later.
