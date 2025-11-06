# PAW Intelligence Modules

This directory contains standalone intelligence gathering modules for PAW (Python Automated Workflow). These modules perform active reconnaissance and enrichment on suspicious domains/IPs extracted from email analysis.

## Modules Overview

- **`criminal_hunter.py`**: Advanced hunting engine with penetrating content fingerprinting, multi-host campaign analysis, passive DNS, TTL analysis, server fingerprinting, and threat actor correlation.
- **`infrastructure_mapper.py`**: Maps network infrastructure including IP resolution, port scanning, and subdomain enumeration.
- **`threat_intel.py`**: Provides threat actor attribution and risk scoring based on collected data.
- **`le_package.py`**: Generates law enforcement packages with executive summaries and technical evidence.
- **`enrich_last_hunt.py`**: Multi-host enrichment script that adds SSL certificates, HTTP banners, reverse DNS, WHOIS, ASN, and advanced analysis across multiple domains.

## Advanced Features

### 🔍 Penetrating Content Fingerprinting
- **Multi-Method HTTP Probing**: HEAD, GET, POST requests with realistic headers
- **JavaScript Obfuscation Detection**: Identifies eval(), fromCharCode, base64 encoding, hex escaping
- **Form Analysis**: Extracts phishing indicators, credential harvesting patterns
- **Resource Fingerprinting**: CSS, images, external scripts analysis
- **Behavioral Pattern Analysis**: Domain complexity, activity patterns, suspicious patterns

### 🌐 Multi-Host Campaign Analysis
- **URL Extraction & Resolution**: Parses emails for links, resolves redirects, extracts hostnames
- **Cross-Domain Correlation**: Identifies shared infrastructure, ASN clustering, geographic patterns
- **Service Classification**: Distinguishes phishing sites from legitimate services (affiliate platforms, image hosting, URL shorteners)
- **Monetization Pattern Detection**: Identifies revenue-generating phishing campaigns

### 📊 Enhanced Enrichment
- **WHOIS & ASN Intelligence**: Provider identification, geographic attribution, allocation dates
- **SSL Certificate Analysis**: Certificate chains, validation status, SAN domains
- **Network Behavior Profiling**: Connection timing, banner grabbing, port analysis
- **Threat Intelligence Correlation**: Composite fingerprinting for campaign tracking

## Usage

All modules are designed to be standalone and do not require external APIs or third-party services. They use built-in Python libraries (socket, ssl, dns, requests, beautifulsoup4) for network operations.

### Running a Hunt

```python
from paw.intelligence.criminal_hunter import CriminalHunter

hunter = CriminalHunter()
result = hunter.hunt_from_domain("suspicious-domain.com")
print(json.dumps(result, indent=2))
```

### Multi-Host Campaign Analysis

For analyzing phishing emails with multiple links:

```python
from paw.intelligence import analyze_inbox

# Analyze an EML file and hunt all discovered hosts
results = analyze_inbox.analyze_email_campaign("path/to/phishing.eml")
print(f"Analyzed {len(results['hunts'])} hosts in campaign")
```

Or from command line:

```bash
cd PAW
python tools/analyze_inbox.py
```

### Enrichment

After a hunt, enrich the results:

```bash
cd PAW
python paw/intelligence/enrich_last_hunt.py
```

This will update `paw/intelligence/last_hunt.json` with additional WHOIS/ASN data for all analyzed hosts.

### Example Output

A typical hunt result includes:

```json
{
  "domain": "suspicious-domain.com",
  "ip": "1.2.3.4",
  "asn": "AS15169 GOOGLE",
  "hosting": "Google Cloud",
  "ssl": {
    "issuer": "Let's Encrypt",
    "valid_until": "2024-12-31"
  },
  "fingerprint": {
    "content_type": "text/html",
    "js_obfuscation": false,
    "forms": ["login", "password"],
    "resources": ["jquery.js", "bootstrap.css"]
  },
  "risk_score": 85
}
```

### Multi-Host Campaign Analysis

When analyzing phishing emails, the system identifies all linked domains and provides a campaign overview:

- **Infrastructure Clustering**: Groups related domains by IP ranges and hosting providers
- **Service Classification**: Identifies legitimate services (CDNs, image hosts, URL shorteners) vs. malicious infrastructure
- **Campaign Attribution**: Correlates operational patterns across multiple hosts
- **Risk Assessment**: Provides overall campaign risk score based on combined analysis

## Requirements

- Python 3.8+
- requests
- beautifulsoup4
- dnspython

Install dependencies:

```bash
pip install -r requirements.txt
```

## Architecture

The intelligence module follows a modular design:

- **CriminalHunter**: Core hunting engine with fingerprinting capabilities
- **Enrichment**: Post-processing for additional intelligence data
- **Analysis Tools**: Specialized scripts for email and campaign analysis

All components are designed for offline operation and do not require internet connectivity for core functionality.

## Notes

- **Offline Operation**: Core fingerprinting works without internet access
- **Realistic Headers**: Uses browser-like headers to avoid detection
- **Multi-Method Probing**: Tries different HTTP methods for comprehensive analysis
- **Error Handling**: Gracefully handles network timeouts and blocked requests
- **Data Persistence**: Results saved to JSON files for further analysis

## Troubleshooting

- **Connection Timeouts**: Increase timeout values in CriminalHunter constructor
- **Blocked Requests**: The system automatically retries with different user agents
- **SSL Errors**: Certificate validation can be disabled for testing (not recommended for production)
- **WHOIS Rate Limits**: Built-in delays prevent rate limiting on WHOIS servers

## Permissions and Security

- **Network Egress**: These modules perform active network probing (DNS, TCP connections, SSL handshakes). Ensure you have authorization before running against production targets.
- **Rate Limiting**: Built-in delays and timeouts prevent overwhelming targets. Respect robots.txt and legal boundaries.
- **Data Handling**: Results are stored locally in JSON format. No data is transmitted externally.

## Example Advanced Output

From a recent advanced hunt on `www.hxzf4er.com`:

```json
{
  "target_domain": "www.hxzf4er.com",
  "real_ips": [
    {
      "ip": "35.201.124.57",
      "technique": "direct_dns",
      "confidence": "high"
    }
  ],
  "infrastructure": {
    "primary_domain": "www.hxzf4er.com",
    "primary_ip": "35.201.124.57",
    "related_domains": ["57.124.201.35.bc.googleusercontent.com"],
    "open_ports": [80, 443],
    "advanced_analysis": {
      "temporal_patterns": {
        "dns_ttl": 1,
        "ttl_category": "low",
        "evasion_potential": "high"
      },
      "infrastructure_reuse": {
        "ip_class": "A",
        "is_cloud_provider": "unknown",
        "reuse_potential": "medium"
      },
      "content_fingerprinting": {
        "server_header": "unknown",
        "security_headers": ["x-eflow-request-id"]
      }
    }
  },
  "infrastructure_clusters": {
    "asn_clusters": [
      {
        "asn": "396982",
        "provider": "Google Cloud",
        "ips_in_cluster": ["35.201.124.57"],
        "confidence": "high"
      }
    ],
    "cloud_providers": ["Google Cloud"],
    "geographic_clusters": ["US"]
  },
  "campaign_correlation": {
    "similar_domains": ["hxzf4er.com"],
    "shared_infrastructure": ["Google Cloud"],
    "temporal_patterns": ["low_ttl_domains"],
    "technique_patterns": ["nginx_phishing", "cloud_hosting_evasion"]
  },
  "operational_fingerprints": {
    "server_config": {
      "nginx_detected": true,
      "version_pattern": "nginx",
      "uniqueness_score": 0.7
    },
    "http_headers": {
      "custom_headers": ["x-eflow-request-id"],
      "security_headers": [],
      "pattern_score": 0.8
    },
    "dns_patterns": {
      "ttl_evasion": true,
      "dynamic_domains": true
    },
    "ssl_patterns": {
      "cert_domains": [],
      "self_signed": false
    }
  },
  "threat_intel": {
    "threat_actor": "Unknown Cybercrime Group",
    "risk_score": 20,
    "campaigns": ["Generic Phishing"]
  },
  "enrichment": {
    "35.201.124.57": {
      "reverse_dns": {"ptr": "57.124.201.35.bc.googleusercontent.com"},
      "ssl_cert_host": {},
      "port_banners": {
        "80": "HTTP/1.0 204 No Content\\r\\nserver: nginx...",
        "443": "{\\"recv_error\\": \\"timed out\\"}"
      },
      "whois": {
        "registrar": null,
        "organization": null,
        "creation_date": null,
        "raw": "No match for domain..."
      },
      "asn": {
        "asn": "396982",
        "prefix": "35.200.0.0/15",
        "country": "US",
        "registry": "arin",
        "allocated": "2017-06-15"
      }
    }
  }
}
```

## Advanced Attribution Techniques

The CriminalHunter implements several advanced techniques for deeper attribution:

### ✅ Infrastructure Cluster Identification
- **ASN Clustering**: Groups IPs by Autonomous System Numbers and providers
- **IP Range Analysis**: Identifies shared IP ranges and cloud provider blocks  
- **Cloud Provider Detection**: Recognizes AWS, Google Cloud, Azure, Cloudflare patterns
- **Geographic Clustering**: Groups by country/registry for attribution

### ✅ Campaign Correlation  
- **Similar Domain Detection**: Finds domains with common patterns (e.g., *.hxzf4er.*)
- **Shared Infrastructure**: Identifies common hosting providers and IP ranges
- **Temporal Patterns**: Analyzes domain registration timing and TTL patterns
- **Technique Patterns**: Recognizes common phishing techniques (nginx pages, cloud hosting)

### ✅ Operational Technique Fingerprinting
- **Server Configuration**: Identifies nginx/Apache with uniqueness scoring
- **HTTP Headers Pattern**: Analyzes security headers and custom X- headers
- **DNS Patterns**: TTL analysis for evasion detection (TTL=1 indicates temporary domains)
- **SSL Patterns**: Certificate analysis for domain clustering
- **Content Patterns**: HTML template and asset fingerprinting

## Configuration

- Timeouts and retries are configurable in the code (e.g., `safe_getcert` uses exponential backoff).
- For production use, consider adding CLI flags to control hunting behavior (see proposed expansions).

## Dependencies

- Python 3.8+
- Standard library only (no external packages required)

## Future Expansions

- Integration into PAW case reports
- Additional unit tests
- CLI opt-in flags for controlled execution</content>
- CLI opt-in flags for controlled execution
