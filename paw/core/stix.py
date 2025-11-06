
import json, uuid
from ..util.timeutil import utc_now_iso

def make_stix(case_id, ip, domain, asn_org):
    bundle_id = f"bundle--{uuid.uuid4()}"
    ip_obj = {
      "type": "observed-data",
      "id": f"observed-data--{uuid.uuid4()}",
      "created": utc_now_iso(),
      "modified": utc_now_iso(),
      "number_observed": 1,
      "objects": {
        "0": {"type": "ipv4-addr", "value": ip}
      }
    }
    dom_obj = {
      "type": "observed-data",
      "id": f"observed-data--{uuid.uuid4()}",
      "created": utc_now_iso(),
      "modified": utc_now_iso(),
      "number_observed": 1,
      "objects": {
        "0": {"type": "domain-name", "value": domain}
      }
    }
    rep = {
      "type": "report",
      "id": f"report--{uuid.uuid4()}",
      "name": f"Phishing Attribution {case_id}",
      "published": utc_now_iso(),
      "object_refs": [ip_obj["id"], dom_obj["id"]]
    }
    bundle = {"type":"bundle","id":bundle_id,"objects":[ip_obj, dom_obj, rep]}
    return bundle
