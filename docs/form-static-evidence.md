# Supplied HTML form observations

`paw/core/form_analysis.py` inventories supplied HTML with schema version 2.
It performs no requests, DNS resolution, rendering, script execution or form
submission. The reproduced version-1 failures were incorrect relative/query
action joining, a Stripe lookalike hostname classified with high confidence,
lost duplicate attributes, overwritten field-category matches and two forms on
one page counted as a cross-page pattern. Static strings cannot establish a
merchant, payment ecosystem, risk, operator or campaign.

## Sources and interpretations

The source SHA-256 covers the complete admitted **supplied Unicode string encoded
as UTF-8**, with its byte length. It is not a hash of original HTTP response bytes.
Nodes identify a start-tag occurrence by `tag_index`, one-based line and
zero-based column. Ordered attributes preserve duplicates, parser-decoded
character references and declared values. Attribute names are parser-normalized
to lowercase. Match offsets are zero-based Python character offsets within the
specified attribute value or the complete supplied string; they are not byte
offsets into a response. The caller must preserve that exact source separately.

`forms`, `unassigned_controls`, `base_observations` and `script_observations`
retain markup occurrences. Controls include input, select, textarea and button
attributes. Nested forms are associated using lexical nesting, **not browser DOM
repair or form ownership**. A control outside that nesting stays unassigned even
if it declares `form=id`; option contents, live values, event handlers and actual
submission fields are not interpreted. Comments, script/style/title/textarea
contents and template contents cannot introduce form/control occurrences.
Self-closing tags follow `HTMLParser` callbacks, not browser parsing rules.

Action/method/src/href declarations distinguish absent, bare, duplicate and
limited attributes. Duplicate or incomplete declarations are not selected.
Method spelling is preserved without an inferred GET/POST default. The derived
action candidate is separate from the declared action. `urllib.parse.urljoin`
uses the supplied page URL and the first retained href-bearing base declaration;
an ambiguous or unusable first declaration prevents fallback to a later base or
the page URL. Empty declared actions/hrefs can join to a supplied page context;
absent/bare values cannot. Omitted contexts prevent assuming that no base was
declared. Absolute actions can still yield candidates without a base.
Only HTTP(S) candidates with a parsed hostname/port and no ASCII whitespace or
control characters are retained. This is a conservative string interpretation,
not browser navigation, URL safety or endpoint validation. `resolution_context`
records the unverified join context and selected base tag occurrence.

All existing field and processor patterns remain available as unverified lexical
observations. Multiple field categories and repeated matches are retained rather
than selecting a single category. Processor observations distinguish an exact
script-src **parsed hostname literal** from registry-token matches anywhere in
the supplied text, including comments and templates. A Stripe lookalike may
contain the text `stripe`; it is not an exact Stripe hostname match. Neither kind
establishes a loaded SDK or payment processing. Source arrays replace unsupported
inferences: compatibility payment/risk/correlation arrays stay empty and
`attribution_hints` reports unavailable interpretation. The retained cross-page
API also reports unavailable campaign correlation (S10).

## Bounds and partial inventory

Defaults: 1 MiB UTF-8 source, 128 forms, 2,048 controls, 128 combined base/script
nodes, 8,192 attributes, 2,048 combined field/processor observations and 4,096
characters per value or derived URL. Limits must be positive integers, excluding
booleans. Invalid HTML types/Unicode or oversized sources are rejected without
prefix analysis or a misleading complete source hash. Invalid/oversized page
context does not discard the admitted HTML inventory.

Counts are global per call. Coverage counts form/control/context occurrences
encountered outside inert/template scopes; attribute counts cover admitted nodes
only. Controls in omitted forms are counted as omitted. Attribute-free base tags
also consume the context budget. Oversized attribute names/values keep bounded
previews and hashes of complete decoded values, but are not reinterpreted as
declarations or hints. Derived URLs have a separate size check. Omitted nodes,
attributes/observations, limited values, detected parser failures and unfinished
lexical scopes produce `partial` with explicit issues/counts. `completed` only
means the supported static inventory finished; it does not validate HTML syntax,
browser semantics, authenticity or benignness. Recovery/acceptance of malformed
markup depends on the supported Python `HTMLParser` version.

## Existing consumer and verification scope

The identified producer is `paw/detonate/runner.py:generate_enrichment_files`,
which supplies `page.content()` and writes `enrichment_forms.json`. It then feeds
the result to `AttributionMatrix`. Its network stages run before this helper and
are not invoked for this verification. The form source is a DOM snapshot; a
previously saved kit page is not guaranteed to equal that later snapshot. The
collector's source retention/atomic publication and dynamic collection remain
open S14 work. This PR does not claim a validated active collector.

The version-2 matrix consumer records static occurrence counts, source hash and
partial/completed status with **unavailable confidence**, avoiding its legacy
count-to-confidence/payment-processor interpretation. Other matrix sources and
legacy version-1 imports are outside this correction. The operator dataset is
unavailable; these form observations supply no automatic correlation keys.

`tests/test_form_observations.py` exercises actual parsing, admission, duplicate
and malformed declarations, multi-category matches, hostname lookalikes, inert
contexts, lexical ownership and all budget families. It also runs the actual
matrix, local atomic JSON writes, evidence seal/verification and ZIP export
under the Python offline policy using a constructed static fixture with no
writers. This is not a substitute for a browser/active-enrichment run or
independent phishing labels. The full `--no-egress` worker skips the active
caller. Its separate `paw/deobfuscate/html.py` form inventory is unchanged and
has independent actual CLI regression checks. The Python policy is not OS
isolation; controlled egress remains deferred.

The recorded local Windows/Python 3.13 check for this correction passed 31 form
contracts and the general suite (568 tests, 560 pass, eight platform exclusions).
The actual shared CLI/API ownership/read/verify/export and supervisor-crash
recovery check passed, as did five actual `full --no-egress` HTML worker cases.
The built wheel matched Python metadata/entry points and all 90 current package
Python files byte for byte. This is not a new clean dependency installation or
a repeated private-corpus/classification evaluation. The source audit found
only this helper and its version-2 matrix consumer changed among those 90 files;
all original processor/field registry patterns were preserved.
