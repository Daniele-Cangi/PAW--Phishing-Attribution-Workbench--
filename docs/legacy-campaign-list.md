# Legacy campaign listing

`python /path/to/checkout/_list_campaigns.py` is a checkout alias for
`paw monitor list`. It uses the current working directory's Sentinel configuration
and the existing passive database admission. It works from another directory
without a host `PYTHONPATH` or installed PAW package; normal project dependencies
are required, as for the canonical CLI.

The old script ignored configuration, opened a hardcoded `sentinel.db` for writing
and created an empty database before failing when storage was missing. It also
queried storage at import time. The alias now runs only as a script (or explicit
`main()` call); import does not access storage or import PAW. Arguments are
forwarded to the canonical command so help and invalid-option handling match.

Output adopts the canonical CLI format: campaign ID, URL and stored status replace
the former case-ID/URL listing. Only active saved campaigns are listed. Missing,
malformed or unsupported storage fails explicitly; it is not an empty healthy
campaign list. No migrations, network monitor or collector are invoked.

`tests/integration_legacy_campaign_list_real.py` runs 26 actual processes:
paired canonical/legacy dispatch for ten storage/configuration states, paired
help/invalid options, inert import and direct script help from outside the checkout
without `PYTHONPATH`. Sources are preserved byte for byte. Dispatch tests use the
Python no-egress guard after ordinary CLI bootstrap; they are not a cold-import
or OS isolation attestation, nor an atomic snapshot of concurrent SQLite writers.

This dispositions one S12 legacy entry point. Campaign writers, other operational
scripts, file helpers and active collection remain separate audit work. No
classifier or attribution accuracy follows from listing stored rows.
