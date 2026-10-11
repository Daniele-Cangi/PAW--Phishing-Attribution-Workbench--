# MIME CID candidate relationships

Nine actual supervised `full --no-egress` cases reproduced a local extraction
gap: HTML attributes, ordered Content-ID fields and attachment bytes were
preserved separately, without a structured relationship between them. The
fixtures cover repeated IDs/fields, percent/entity encodings, missing/case-distinct
IDs, nested messages, attached HTML and complex attribute values. They are
regression evidence, not independently labeled phishing samples.

## Observation and candidate contract

New cases add `mime_cid_inventory.json`. Its HTML source catalog references
supported non-attached outer HTML body parts, their message scope, persisted
charset-text input paths/hashes/status and `mime_body_evidence.json`. Attribute
values are derived with a fresh standard HTML parser per part; character
references have already been interpreted. Element/attribute ordinals describe
that parser view, not original byte positions or a rendered DOM.

Whole values beginning with a case-insensitive `cid:` scheme are observed in
`src`, `href`, `action`, `formaction`, `poster`, `data`, `background`, `cite`,
`longdesc` and `usemap`. Values in `style`/`srcset` containing a `cid:` marker
are retained as complex attribute observations; CSS/srcset grammar is not
parsed and those observations create no candidate links. Script contents,
comments, CSS text, other attributes, relative Content-Location references,
`mid:` and attached/embedded HTML are outside this extraction scope.

Content-ID catalog records reference every retained named Content-ID field in
`mime_header_inventory.json`, its parser field index, part ID and message-root
scope. Duplicate fields and parts remain separate. Parsed fields unavailable
under upstream header budgets, unsupported identifier forms and new value
capture limits remain explicitly un-interpreted, with a reason. Omitted fields,
nodes and unknown field names make candidate inventory completeness false.

The conservative comparison removes one angle-bracket pair from a captured
header value, decodes percent escapes once from a direct CID attribute and
compares supported ASCII identifiers case-sensitively within the same captured
message-root scope. Empty/non-ASCII/whitespace/control/angle-bracket identifiers
and malformed percent escapes remain uninterpreted. This is candidate string
equality, not validation of full RFC addr-spec syntax. It does not choose a
resource or infer successful rendering, attachment content safety, identity or
authentication. Multiple fields with equal identifiers remain ambiguous.
Inner-message Content-IDs never become candidates for outer HTML references.

[RFC 2392](https://www.rfc-editor.org/info/rfc2392/) describes CID addressing
and percent interpretation; it also requires MIME context rules for selecting
between repeated IDs. [RFC 2387](https://www.rfc-editor.org/info/rfc2387/) defines
multipart/related context. PAW inventories candidate equality and preserves
the existing tree context; it does not implement a conforming CID renderer or
multipart alternative/related resource selection.

## Bounds, counts and uncertainty

Default budgets retain 2,048 attribute observations, 4,096 candidate links,
4,096 UTF-8 bytes per captured value and 262,144 total captured value bytes.
The last budget spans Content-ID identifiers and parsed attribute values;
source/header records continue to point to their existing original evidence.
The Content-ID/source catalogs are additionally bounded by upstream MIME/header
node/field limits. Body parsing uses the existing text/input/depth budgets.

Total/inventoried/omitted observation counts cover all supported direct/complex
attribute observations. Direct references and complex marker attributes have
separate counts. A complex attribute can contain several CID-like substrings;
its count is one attribute observation, not a CID occurrence count.
`total_link_count` counts matching candidate fields only for **retained
observations and interpreted captured Content-ID fields**, as recorded by
`link_count_scope`. It is not a count of hypothetical matches for omitted or
uninterpreted observations/fields. Candidate counts remain complete within that
scope before the ordered link-prefix retention limit. Link omissions, value
limits, malformed/unavailable interpretations and header completeness are
explicit. An unmatched observation means no equality in the captured supported
fields; it does not prove the original email has no resource with that identity.

Completion means completion within this observation scope, including unmatched
or ambiguous candidates. Partial capture/interpretation remains explicit. A
candidate match is always unverified and does not add risk or attribution points.

## Publication and verification

The catalog is published atomically after its header/body source artifacts
exist. Original source hashes and captured body text hashes are checked; no
attachment file path is claimed before attachment preservation. API detail,
technical report, assessment coverage, seals and ZIP expose the artifact. Older
cases without it remain readable. Existing URL records/targets, body/attachment
representations, selected sender/authentication logic and numeric scores stay
unchanged; no references are visited and no resource is rendered or executed.

Ten contracts cover provenance, aliases, repeated fields, independent parser
state, inner/attached scope, invalid forms, limits/count scopes, input binding
and no-egress. Thirteen actual CLI cases and five loopback HTTP workers check
fixed candidate expectations, source files/hashes, coverage, API/ZIP and seals.
Actual limits include 5,000 candidate pairs with 4,096 retained/904 omitted,
2,050 observations with 2,048 retained/2 omitted, and uncaptured oversized values.
