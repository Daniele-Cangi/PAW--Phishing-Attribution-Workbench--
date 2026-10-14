# Legacy origin updater boundary

`scripts/update_origin.py` is an explicitly unavailable legacy entry point,
consistent with the existing `paw update`/`update_report` disposition. Direct
execution exits 1 with a reason; `--help` documents the boundary, invalid options
exit 2 and import has no operational side effects. It needs only the standard
library and works outside the checkout without an installed package or host
`PYTHONPATH`.

The old script used a hardcoded case path, imported an active WHOIS/RDAP collector,
read the case at import time and overwrote `origin.json`. Its exception handler
discarded the lookup error and replaced existing ASN, organization, country and
abuse observations with NULL/empty values, returning success. Actual local sealed
files reproduced this for execution and import with a documentation IP rejected
by the real dependency before a request: original fields were erased and the
existing seal failed. This was a filesystem regression fixture, not an analyzed
email or evidence of live provider behavior. Dependency bootstrap preceded the
guard in that baseline probe; the legacy script itself ran under the guard.

The entry point now rejects before any case/source access or collector import.
It does not update, reseal or fabricate replacement evidence. A new supervised
`paw full INPUT --no-egress` analysis creates a separate case while preserving
existing cases. Future updates/enrichment require separately admitted versioned
observations, provider/time/error provenance, ownership and sealing contracts,
and controlled egress validation in S14. This change neither implements those
capabilities nor changes the package's existing unavailable update command.

`tests/integration_legacy_origin_update_real.py` performs one actual supervised
full analysis of original EML bytes under no-egress. After confirmed worker-tree
shutdown and seal verification, 24 cold guarded processes exercise execute,
import, help and invalid arguments across completed/sealed, missing, unsealed,
malformed, blocked-owner metadata and missing-origin filesystem states. The old
hardcoded path contains an additional real sealed filesystem fixture with saved
origin fields. Two direct script processes also run outside the checkout without
`PYTHONPATH`. All source bytes, original EML, seals and saved fields remain
unchanged. The guard observes no collector imports, new thread or blocked
operation; an additional audit hook rejects source filesystem access instead of
relying only on before/after hashes.

Ownership-state fixtures do not establish a live process; the actual EML analysis
supplies completed-worker evidence only. The Python guard/audit checks are not OS
containment. Successful sealing/verification does not establish message
authenticity, origin attribution or classifier accuracy. Other operational
scripts, active enrichment and general versioned publication remain separate
audit work. S12 can disposition this script as explicitly unavailable without
silently losing stored forensic observations.
