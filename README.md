# PAW — Phishing Attribution Workbench

**Attribution-Only Email Forensics Tool**

PAW (Phishing Attribution Workbench) è uno strumento specializzato per l'analisi forense di email di phishing. Ingestisce file `.eml` e `.msg`, ricostruisce l'origine dell'attacco (IP→ASN→Organizzazione→Paese), valida autenticazioni SPF/DKIM/DMARC, analizza anomalie negli header, rileva pattern di campagna, e produce un dossier completo con grafi, bundle STIX, e package di abuso portabili.

## 🚀 Caratteristiche Principali

### Core Attribution Engine
- **Ricostruzione Origine**: Traccia l'IP di origine attraverso il path `Received`
- **Classificazione Boundary**: Identifica hop MX interni vs internet origin
- **Risoluzione Infrastruttura**: ASN, organizzazione, geolocalizzazione
- **Validazione Autenticazione**: SPF, DKIM, DMARC, ARC, Received-SPF

### Advanced Intelligence Integration 🚀
- **Criminal Hunter**: Analisi automatica infrastrutturale criminale post-detonazione
- **Infrastructure Mapper**: Mappatura avanzata rete C2 e servizi attivi
- **Enrich Last Hunt**: SSL certificates, service banners, WHOIS/ASN intelligence
- **Threat Intelligence**: Correlazione automatica con VirusTotal, AbuseIPDB, AlienVault, ThreatFox
- **Attribution Matrix**: Matrice unificata di pivot con integrazione intelligence

### Accurate Geolocalization
- **Physical Location Priority**: Utilizza posizione fisica dell'IP (network.country) invece del paese di registrazione ASN
- **Historical ASN Tracking**: Mantiene traccia del paese di registrazione ASN per analisi forense completa
- **Smart Scoring**: Penalizza solo quando sia posizione fisica che ASN sono in paesi high-spam
- **RDAP Integration**: Query WHOIS/RDAP per dati infrastrutturali accurati e completi

### Advanced Threat Detection
- **Header Forgery Guard**: Rileva iniezioni e anomalie negli header con analisi sofisticata (IP-FQDN mismatch, relay chains sospetti, manipolazione timestamp)
- **Brand Identity Heuristics**: Display-name spoofing, TLD rischiosi, NRD analysis
- **Campaign Correlation**: Pattern detection attraverso correlazione casi
- **Trust Boundary Engine**: Classificazione MX per O365/Gmail/Yahoo/Proton
- **Deobfuscation Engine**: Smaschera URL offuscati, caratteri invisibili, encoding multi-layer
- **Enhanced Attachment Analysis**: Scansione avanzata allegati con rilevamento macro OLE, firme malware, metadati sospetti

### Advanced Intelligence Features 🚀

PAW integra automaticamente moduli di intelligence avanzati per analisi infrastrutturale completa e correlazione threat intelligence:

#### Criminal Hunter Integration
- **Automatic Infrastructure Analysis**: Post-detonazione analisi criminale degli endpoint C2
- **Local Intelligence Primitives**: Utilizzo di primitive locali (DNS, SSL, socket) senza API esterne
- **Criminal Attribution**: Identificazione pattern infrastrutturali criminali
- **Output**: `criminal_intelligence.json` con analisi dettagliata per dominio

#### Infrastructure Mapper
- **Advanced Network Mapping**: Mappatura completa dell'infrastruttura di rete
- **C2 Infrastructure Detection**: Rilevamento server C2 e pattern di comunicazione
- **Service Fingerprinting**: Identificazione servizi attivi su porte comuni
- **Output**: `infrastructure_mapping.json` con mappatura dettagliata IP e servizi

#### Enrich Last Hunt
- **SSL Certificate Enrichment**: Analisi certificati SSL per tutti gli endpoint
- **Service Banner Grabbing**: Cattura banner servizi (HTTP, FTP, SSH, SMTP, etc.)
- **Reverse DNS & WHOIS**: Risoluzione DNS inversa e lookup WHOIS
- **ASN Intelligence**: Informazioni ASN per geolocalizzazione avanzata
- **Output**: `hunt_enrichments.json` con arricchimenti completi infrastrutturali

#### Threat Intelligence Correlation
- **Multi-Source Intelligence**: Correlazione automatica con VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox
- **Domain & IP Enrichment**: Arricchimento indicatori da tutti i risultati analisi
- **Intelligence Scoring**: Valutazione affidabilità fonti intelligence
- **Output**: `threat_intelligence.json` con correlazioni threat intelligence

#### Automatic Attribution Matrix Enhancement
Tutti i moduli intelligence si integrano automaticamente nell'`attribution_matrix.json`:
- **Unified Pivots**: Pivot unificati per identificazione operatore
- **Confidence Scoring**: Punteggio confidenza basato su correlazioni multiple
- **Cluster Analysis**: Raggruppamento host con caratteristiche comuni
- **Abuse Targeting**: Identificazione contatti abuse ottimizzati

### Advanced Deobfuscation Module
- **URL Deobfuscation**: Percent-encoding, base64, hex escapes, homograph attacks
- **HTML Analysis**: Entity decoding, hidden elements, form obfuscation, iframe detection
- **JavaScript Deobfuscation**: String.fromCharCode, atob/btoa, eval detection, iterative decoding
- **Text Normalization**: Character substitution, homoglyph attacks, phishing abbreviations
- **Multi-layer Analysis**: Deoffuscamento iterativo con scoring di sospetto
- **Email Filtering**: Distinzione automatica tra URL dannosi e indirizzi email legittimi

### Scoring System Avanzato
- **Multi-layered Scoring**: Header integrity, domain signals, identity checks
- **Profile System**: `default`, `strict`, `conservative` per adattare soglie
- **Campaign Boost**: +0.20 per pattern multi-caso rilevati
- **Real-time Decision**: "Likely malicious", "Suspicious", "Inconclusive"

### Output Production
- **Evidence Capsule**: Package portabile con tutti gli artefatti
- **Mermaid Graphs**: Visualizzazione path di consegna e relazioni
- **STIX Bundle**: Export per piattaforme SOAR/SIEM
- **Abuse Package**: Template pronti per report abuse

### PATCH PACK — Advanced Attribution (Detonation + Deobfuscation + Canary)
- **Observational Detonation**: Browser Playwright per analisi URL sicure (block POST/PUT/PATCH/DELETE)
- **Interactive Encrypted Clicking**: Profilo avanzato con crittografia end-to-end e simulazione interazioni
- **Network Capture**: Cattura requests, downloads, endpoints contattati con TLS fingerprinting
- **Endpoint Resolution**: Risoluzione IP per infrastruttura C2/tracker con DNS enrichment
- **Passive Canary**: Server per attribuzione visitatori (IP/UA logging)
- **Advanced Deobfuscation**: Smaschera tecniche di offuscamento avanzate nei phishing
- **Campaign Integration**: Bonus scoring per pattern multi-vettore
- **Legal Safe**: Policy guard (observe-only, no interaction senza consenso)

## 📦 Installazione

### Prerequisiti
- Python 3.8+
- pip

### Setup Ambiente
```bash
# Crea virtual environment
python -m venv .venv

# Attiva (Linux/Mac)
source .venv/bin/activate

# Attiva (Windows)
.venv\Scripts\activate

# Installa dipendenze
pip install -r requirements.txt
```

### Dipendenze Chiave
- `requests` - API calls per geolocalizzazione e WHOIS
- `dnspython` - DNS resolution e DMARC lookup
- `cryptography` - Validazione certificati e firme
- `beautifulsoup4` - HTML parsing per deoffuscamento avanzato
- `pgpy` - PGP signing (opzionale)
- `extract-msg` - Supporto file .msg
- `python-magic` - File type detection

## 🎯 Utilizzo Base

### Analisi Singola Email
```bash
# Analizza email con scoring base
python -m paw trace --src email.eml

# Analizza directory di email
python -m paw trace --src inbox/

# Con output avanzati e deoffuscamento
python -m paw trace --src inbox/ --stix --abuse --lang it --no-egress
```

### Deoffuscamento Avanzato
```bash
# Analizza email con deoffuscamento completo (default)
python -m paw trace --src phishing.eml

# Analizza senza detonazione esterna (--no-egress)
python -m paw trace --src phishing.eml --no-egress

# Deoffusca contenuto specifico
python -c "
from paw.deobfuscate.core import DeobfuscationEngine
engine = DeobfuscationEngine()
result = engine.analyze_artifacts({
    'text': 'Contenuto con URL offuscati',
    'urls': ['hxxps://evil[.]com', 'https%3A//bad.com']
})
print(result)
"
```

**Output Deoffuscamento**: `[deobfuscate] discovered hidden URL: https://real-malicious-site.com`

### Verifica Caso Esistente
```bash
python -m paw verify --case cases/case-2025-10-28T131823Z-c77d
```

### Query Database Casi
```bash
# Cerca per IP
python -m paw query --by ip --value 192.168.1.1

# Cerca per dominio
python -m paw query --by domain --value evil.com

# Cerca per ASN
python -m paw query --by asn --value 12345
```

### Export Caso
```bash
python -m paw export --case cases/case-id --format zip
```

## 🔬 PATCH PACK — Detonation + Canary

### Detonazione Osservativa
## 🚀 Utilizzo

PAW fornisce **3 entrypoint principali** per workflow forense scalabili:

### 1. 📧 Trace (Ingest + Attribuzione - No Egress)
**Scopo**: Analisi primaria forense senza connessioni di rete esterne.

```bash
# Analisi base email (no egress by default)
python -m paw trace --src phishing.eml

# Con profilo scoring specifico
python -m paw trace --src phishing.eml --profile strict --lang it

# Directory di email
python -m paw trace --src /path/to/emails/ --stix --abuse

# Forensics avanzati
python -m paw trace --src email.eml --deob-weight 0.4 --anchor
```

**Output**: `cases/<case>/report/` - dossier completo forense

### 2. 🔍 Detonate (Egress Osservativo)
**Scopo**: Mappare infrastruttura phishing con capture di rete controllata.

```bash
# Detonazione osservativa (block POST/PUT/DELETE)
python -m paw detonate --url https://suspicious-site.com --observe --pcap

# Da case esistente (URLs estratte da trace)
python -m paw detonate --case case-20251029-XXXX --observe --timeout 45

# Encrypted clicking per analisi interattiva
python -m paw detonate --case case-20251029-XXXX --encrypted --phishing-type banking
```

**Output**: `cases/<case>/detonation/` + enrichment files + `attribution_matrix.json`

### 3. 🕸️ Canary (Server Passivo)
**Scopo**: Tracciare visitatori dei link canarino per attribuzione campagne.

```bash
# Avvia server canary per case
python -m paw canary --case case-20251029-XXXX --port 8787

# Link canarino da condividere (ambiente sicuro!)
# http://<your-public-ip>:8787/t/<token>
```

**Output**: `cases/<case>/canary/hits.jsonl` - IP/UA visitatori

### 🔄 Workflow Tipico
```bash
# 1. Analisi iniziale (sicura, no egress)
python -m paw trace --src phishing.eml

# 2. Detonazione se necessaria (ambiente controllato)
python -m paw detonate --case <generated-case-id> --observe

# 3. Canary per tracking campagne (opzionale)
python -m paw canary --case <case-id> --port 8787
```

**Output**: `cases/<case>/detonation/{requests.jsonl,summary.json,downloads/,capture.pcap}`

**Detonation Enrichment**:
- `trackers.json` - Analytics IDs (GTM/GA4/FB Pixel/TikTok/Matomo) per correlazione campagne
- `tls.json` - Certificate SPKI hash per pivot tra host diversi con stessa chiave
- `redirect_chain.json` - Shortener full-chain (hop, status, timing, UTM params)
- `dns_enrichment.json` - CNAME/NS/Reseller mapping per pattern hosting
- `tls_fingerprint.json` - JA3S/ALPN fingerprinting server costante
- `forms.json` - Form/payment hints parsing (PSP patterns, merchant correlation)

**Encrypted Output**: `cases/<case>/detonation/encrypted/{analysis.enc,interactions.json.enc,screenshots.enc}`

**Attribution Matrix**: `cases/<case>/attribution_matrix.json` - Pivot unificati per arrivare alla fonte (linkato in executive.md)

### Struttura Attribution Matrix
L'Attribution Matrix unifica tutti i pivot forensi per identificare l'operatore dietro la campagna:

```json
{
  "case_id": "case-20251029-XXXX",
  "operator_hypothesis": {
    "confidence": 0.85,
    "hypothesis": "Eastern European hosting provider, cryptocurrency payment processor",
    "evidence_count": 12
  },
  "pivots": [
    {
      "type": "tls_fingerprint",
      "source": "JA3S fingerprint",
      "value": "abc123...",
      "matches": ["campaign_001", "campaign_002"],
      "weight": 0.9
    },
    {
      "type": "tracker_id",
      "source": "Google Analytics",
      "value": "UA-12345678-9",
      "matches": ["phish_domain_1", "phish_domain_2"],
      "weight": 0.8
    },
    {
      "type": "reseller_pattern",
      "source": "DNS enrichment",
      "value": "namecheap_shared_hosting",
      "matches": ["ip_1.2.3.4", "ip_5.6.7.8"],
      "weight": 0.7
    }
  ],
  "clusters": [
    {
      "cluster_id": "cluster_001",
      "pivot_types": ["tls_fingerprint", "tracker_id"],
      "hosts": ["evil.com", "bad.net", "phish.org"],
      "operator_hint": "Likely same actor based on TLS + GA overlap"
    }
  ],
  "abuse_targets": [
    {
      "type": "hosting_abuse",
      "contact": "abuse@hoster.com",
      "priority": "high",
      "evidence": "3 domains with same TLS fingerprint"
    }
  ]
}
```

### Canary Passivo
```bash
# Avvia server canary per case
python -m paw canary --case case-20251027-XXXX --port 8787
```

**Link canarino**: `http://<TUO_IP_PUBBLICO>:8787/t/<token>` (usa solo in ambienti sicuri!)

**Output**: `cases/<case>/canary/hits.jsonl` → `canary_ips.json`

## 📊 Report Generation & Attribution

### Executive Summary Enhancement
Il report `executive.md` include ora una sezione **"Operator Hypothesis"** basata sui pivot correlati:

```
## Operator Hypothesis (LLM-Free Attribution)

### Ricorrenze Identificate
- **TLS Fingerprint JA3S**: `abc123...` (4 host, 3 campagne)
- **Google Analytics**: `UA-12345678-9` (2 domini phishing)
- **Reseller Pattern**: Namecheap shared hosting (6 IP)

### Ipotesi Operatore
**Confidence: 85%** - Operatore Eastern European con infrastruttura condivisa, pagamento crypto, focus su campagne italiane di emergenza auto.

### Destinatari Abuse
1. **hosting_abuse@namecheap.com** (Priority: High) - 6 IP con stesso reseller
2. **cert-abuse@digicert.com** (Priority: Medium) - Certificato wildcard sospetto
3. **abuse@google.com** (Priority: Low) - GA tracking su siti phishing
```

### Attribution Matrix Integration
L'`attribution_matrix.json` alimenta automaticamente l'Operator Hypothesis con:
- **Cluster Analysis**: Gruppi di host con pivot comuni
- **Confidence Scoring**: Peso evidenza basato su correlazioni multiple
- **Abuse Targeting**: Contatti ottimizzati per massima efficacia

### File Output Structure
```
cases/<case>/
├── report/
│   ├── executive.md          # Summary + Operator Hypothesis
│   ├── technical.md          # Detailed analysis
│   ├── score.json           # Scoring breakdown
│   └── evidence.zip         # Portable package
├── detonation/
│   ├── endpoints.json         # Endpoint contattati
│   ├── requests.jsonl         # Network capture
│   ├── summary.json          # Analysis summary
│   ├── trackers.json         # Analytics IDs
│   ├── tls.json              # Certificate fingerprints
│   ├── redirect_chain.json   # URL expansion
│   ├── dns_enrichment.json   # Hosting patterns
│   ├── tls_fingerprint.json  # JA3S/ALPN
│   ├── forms.json           # Payment hints
│   ├── criminal_intelligence.json    # Criminal infrastructure analysis
│   ├── infrastructure_mapping.json   # Advanced network mapping
│   ├── hunt_enrichments.json         # SSL/banner enrichments
│   └── threat_intelligence.json      # Threat intelligence correlations
├── intelligence/             # Advanced intelligence modules
│   ├── criminal_hunter/     # Criminal analysis results
│   ├── infrastructure/      # Network mapping data
│   ├── enrichments/         # SSL/banner data
│   └── threat_intel/        # Intelligence correlations
├── attribution_matrix.json  # Unified pivots + intelligence
├── c2_infrastructure.json   # C2 infrastructure analysis
├── phishing_kit_analysis.json # Extracted kit analysis
└── canary/
    └── hits.jsonl          # Visitor tracking
```

### Integrazione Scoring
- **+0.15**: Se downloads rilevati durante detonazione
- **+0.10**: Se endpoints esterni al dominio origine
- **+0.20**: Se canary cattura IP pubblici
- **+0.10-0.30**: Bonus deoffuscamento basato su complessità tecniche rilevate
- **+0.15-0.22**: Bonus encrypted clicking per pattern interattivi rilevati
- **+0.25**: Se tracker/analytics IDs correlano con campagne conosciute
- **+0.30**: Se TLS SPKI match con host precedentemente identificati
- **+0.20**: Se redirect chain rivela affiliazioni/UTM tracking
- **+0.15**: Se reseller pattern identifica provider ricorrente
- **+0.25**: Se JA3S fingerprint match con server C2 conosciuti
- **+0.35**: Se Criminal Hunter identifica pattern infrastrutturali criminali
- **+0.25**: Se Infrastructure Mapper rileva C2 infrastructure complessa
- **+0.20**: Se Enrich Last Hunt trova certificati SSL sospetti
- **+0.30**: Se Threat Intelligence correlation conferma attività malevola
- **+0.40**: Se Attribution Matrix mostra cluster operatore ad alta confidenza

## ⚙️ Configurazione Avanzata

### Profili Scoring
```bash
# Strict: più sensibile, meno falsi negativi
python -m paw trace --src email.eml --profile strict

# Conservative: meno sensibile, meno falsi positivi
python -m paw trace --src email.eml --profile conservative

# Default: bilanciato
python -m paw trace --src email.eml --profile default
```

### PGP Signing (Opzionale)
Richiede chiave GPG privata per firma crittografica dei package.

```bash
# Genera chiave GPG
gpg --gen-key

# Esporta chiave privata
gpg --export-secret-keys --armor your@email.com > private.key

# Configura ambiente
export PAW_PGP_PRIV="/path/to/private.key"
export PAW_PGP_PASS="your_passphrase"  # opzionale

# Traccia con firma
python -m paw trace --src email.eml --abuse
```

### Rekor Anchoring (Opzionale)
Timestamping immutabile su Sigstore Rekor per evidence preservation.

```bash
# Genera chiave RSA
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Configura ambiente
export PAW_REKOR_URL=https://rekor.sigstore.dev
export PAW_REKOR_PRIVKEY_PEM="/path/to/private.pem"
export PAW_REKOR_PUBKEY_PEM="/path/to/public.pem"

# Traccia con anchoring
python -m paw trace --src email.eml --anchor
```

## 📊 Sistema di Scoring

### Componenti Score
- **Header Integrity** (0-0.4): SPF fail, DKIM missing, DMARC invalid
- **Domain Signals** (0-0.3): ASN suspicious, NRD <30 giorni, TLD rischioso
- **Identity Checks** (0-0.2): Display-name spoofing, Reply-To mismatch
- **Authentication Advanced** (0-0.8): Received-SPF fail, ARC issues, DMARC policy
- **Deobfuscation Bonus** (0-0.3): URL nascosti rivelati, tecniche avanzate rilevate

### Tuning del contributo del Deoffuscamento

PAW ora integra il risultato dell'engine di deoffuscamento direttamente nello scoring finale.
Di default il contributo massimo che la deoffuscazione può dare al punteggio del dominio è 0.30
(30%). Il valore è applicato come: domain_score += deob_score * deobfuscation_weight,
dove `deob_score` è un aggregato (0.0–1.0) basato su: testo (peso 0.6), URL (peso 0.25) e HTML (peso 0.15).

Come cambiare il comportamento:

- Cambiare il valore predefinito (rapido): modificare la signature di `score_case` in
  `paw/core/scoring.py` (parametro `deobfuscation_weight`). Esempio, aumentare a 0.5 per maggiore impatto.
- Esposizione CLI (consigliato come prossimo step): aggiungere un argomento `--deob-weight` in
  `paw/__main__.py` e passarne il valore a `score_case` da `paw/core/trace.py`.

Ispezione rapida dei risultati di deoffuscamento in un case:

```python
import json
rs = json.load(open('cases/<case>/deobfuscation_results.json'))
da = rs.get('deobfuscated_artifacts', {})
print('Text suspicion:', (da.get('text') or {}).get('suspicion_score'))
print('HTML suspicion:', (da.get('html') or {}).get('suspicion_score'))
urls = da.get('urls', [])
if urls:
    print('Top URL suspicion:', max(u.get('suspicion_score',0) for u in urls))
    print('URLs:', [(u.get('original_url'), u.get('final_url'), u.get('suspicion_score')) for u in urls])
```

Nota: se preferisci che la deoffuscazione non influenzi lo scoring, imposta `deobfuscation_weight` a `0.0`.
- **Campaign Boost** (0-0.2): Pattern multi-caso rilevati

### Soglie Decisione
- **≥ 0.72**: Likely malicious infrastructure
- **≥ 0.55**: Suspicious or compromised account
- **< 0.55**: Inconclusive (richiede analisi manuale)

### Modificatori Profilo
- **Strict**: +0.05 base, soglie più basse (0.68/0.52)
- **Conservative**: -0.05 base, soglie più alte (0.76/0.58)

## 🏗️ Architettura Sistema

### Pipeline di Analisi
1. **Ingest**: Parsing .eml/.msg con estrazione header strutturata
2. **Deobfuscation**: Analisi contenuto per rivelare URL nascosti e tecniche di offuscamento
3. **Path Reconstruction**: Normalizzazione Received headers, classificazione hop
4. **Origin Selection**: Scelta IP origine (preferenza non-MX-internal)
5. **Infrastructure Resolution**: IP→ASN→Org→CC via API
6. **Authentication Validation**: SPF/DKIM/DMARC/ARC parsing e verifica
7. **Anomaly Detection**: Header forgery avanzato, boundary violations, relay chain analysis
8. **Attachment Analysis**: Scansione allegati con rilevamento malware e macro OLE
9. **Detonation Analysis**: Osservazione sicura degli URL rivelati (PATCH PACK)
10. **Criminal Hunter**: Analisi infrastrutturale criminale automatica
11. **Infrastructure Mapping**: Mappatura avanzata rete e servizi C2
12. **Enrichment Hunt**: SSL certificates, service banners, WHOIS/ASN intelligence
13. **Threat Intelligence**: Correlazione automatica con feed esterni
14. **Campaign Analysis**: Correlazione con casi precedenti + intelligence matrix
15. **Scoring**: Calcolo punteggio multi-layered con bonus intelligence
16. **Evidence Generation**: Grafi, STIX, abuse package con attribution completa

### Struttura Caso
```
cases/case-{timestamp}-{hash}/
├── input.eml                    # Email originale
├── manifest.json               # Metadati caso
├── headers.json                # Header estratti
├── auth.json                   # Risultati autenticazione
├── origin.json                 # IP origine risolto
├── received_path.json          # Path di consegna
├── received_anomalies.json     # Anomalie rilevate (header forgery avanzato)
├── attachments.json            # Analisi allegati (malware, macro OLE)
├── deobfuscation_artifacts.json # Artefatti deoffuscamento
├── deobfuscation_results.json   # Risultati analisi deoffuscamento
├── detonation/                 # PATCH PACK - Detonazione osservativa
│   ├── endpoints.json         # Endpoint contattati
│   ├── requests.jsonl         # Requests catturati
│   ├── summary.json           # Analysis summary
│   ├── criminal_intelligence.json    # Criminal infrastructure analysis
│   ├── infrastructure_mapping.json   # Advanced network mapping
│   ├── hunt_enrichments.json         # SSL/banner enrichments
│   ├── threat_intelligence.json      # Threat intelligence correlations
│   └── phishing_kit_analysis.json    # Extracted kit analysis
├── intelligence/               # Advanced intelligence modules
│   ├── criminal_hunter/       # Criminal analysis results
│   ├── infrastructure/        # Network mapping data
│   ├── enrichments/           # SSL/banner data
│   └── threat_intel/          # Intelligence correlations
├── attribution_matrix.json    # Unified pivots + intelligence integration
├── c2_infrastructure.json     # C2 infrastructure analysis
├── canary/                    # PATCH PACK - Server passivo
│   └── hits.jsonl            # IP visitatori catturati
├── report/
│   ├── score.json            # Punteggio e decisione
│   ├── executive.md          # Report narrativo + Operator Hypothesis
│   └── graphs/               # Visualizzazioni Mermaid
├── evidence/
│   ├── rekor_anchor.json     # Rekor timestamp (opzionale)
│   ├── rekor_proof.json      # Rekor inclusion proof
│   └── abuse_package/        # Package per report abuse
└── case_index.json           # Metadati per database
```
```
cases/case-{timestamp}-{hash}/
├── input.eml                    # Email originale
├── manifest.json               # Metadati caso
├── headers.json                # Header estratti
├── auth.json                   # Risultati autenticazione
├── origin.json                 # IP origine risolto
├── received_path.json          # Path di consegna
├── received_anomalies.json     # Anomalie rilevate
├── deobfuscation_artifacts.json # Artefatti deoffuscamento
├── deobfuscation_results.json   # Risultati analisi deoffuscamento
├── detonation/                 # PATCH PACK - Detonazione osservativa
│   ├── endpoints.json         # Endpoint contattati
│   ├── requests.jsonl         # Requests catturati
│   └── downloads/             # File scaricati
├── canary/                     # PATCH PACK - Server passivo
│   └── hits.jsonl             # IP visitatori catturati
├── report/
│   ├── score.json             # Punteggio e decisione
│   ├── executive.md           # Report narrativo
│   └── graphs/                # Visualizzazioni Mermaid
├── evidence/
│   ├── rekor_anchor.json      # Rekor timestamp (opzionale)
│   ├── rekor_proof.json       # Rekor inclusion proof
│   └── abuse_package/         # Package per report abuse
└── case_index.json            # Metadati per database
```

### Database Indicatori
SQLite database `cases/index.db` per correlazione campagne:
- **Cases**: ID, timestamp, origine, punteggio, simhash
- **Indicators**: IP, dominio, ASN, organizzazione per query rapida

## 🔍 Esempi di Analisi

### Caso con Deoffuscamento Avanzato
```json
{
  "deobfuscation_results": {
    "deobfuscated_artifacts": {
      "urls": [
        {
          "original_url": "hxxps://evil[.]com",
          "final_url": "https://evil.com",
          "transformations": [
            {
              "technique": "decodeurl",
              "from": "hxxps://evil[.]com",
              "to": "https://evil.com",
              "description": "Decoded hxxp obfuscation and dot bracket"
            }
          ],
          "suspicion_score": 0.8,
          "suspicion_indicators": ["hxxp_obfuscation", "bracket_notation"]
        }
      ]
    },
    "suspicion_score": 0.75,
    "complexity_rating": "high"
  },
  "score": 0.89,
  "decision": "Likely malicious - Advanced obfuscation techniques detected"
}
```

### Caso Phishing O365 Spoofed
```json
{
  "score": 0.87,
  "decision": "Campaign pattern detected - Likely malicious infrastructure",
  "anomalies": {
    "private_ip_before_boundary": true,
    "invalid_fqdn_count": 2,
    "received_spf_result": "fail"
  },
  "origin": {
    "ip": "185.123.45.67",
    "asn": 12345,
    "org": "Malicious Hosting Ltd",
    "cc": "RU"
  }
}
```

### Caso Legittimo con Forwarding
```json
{
  "score": 0.12,
  "decision": "Inconclusive",
  "anomalies": {
    "non_monotonic_dates": false,
    "private_ip_before_boundary": false
  },
  "origin": {
    "ip": "203.0.113.1",
    "asn": 64496,
    "org": "Gmail",
    "cc": "US"
  }
}
```

### Intelligence Integration Examples

#### Criminal Hunter Analysis
```json
{
  "criminal_intelligence": [
    {
      "target_domain": "evil-phish.com",
      "criminal_analysis": {
        "infrastructure_type": "bulletproof_hosting",
        "risk_level": "high",
        "indicators": ["anonymous_registration", "high_risk_asn", "malware_distribution"],
        "confidence": 0.85
      }
    }
  ]
}
```

#### Infrastructure Mapping
```json
{
  "infrastructure_mapping": {
    "target_domain": "c2-server.com",
    "ip_mappings": [
      {
        "ip": "192.168.1.100",
        "services": ["HTTP", "HTTPS", "FTP"],
        "banners": {
          "80": "Apache/2.4.29 (Ubuntu)",
          "443": "nginx/1.18.0"
        },
        "risk_assessment": "C2_server"
      }
    ],
    "network_topology": "single_hop",
    "c2_indicators": ["unusual_port_usage", "encrypted_c2_protocol"]
  }
}
```

#### Threat Intelligence Correlation
```json
{
  "threat_intelligence": {
    "domain_evil.com": {
      "virustotal": {
        "domain_score": "malicious",
        "detection_ratio": "45/90"
      },
      "abuseipdb": {
        "abuse_confidence": 85,
        "reports": 127
      },
      "alienvault": {
        "pulse_count": 3,
        "related_malware": ["Emotet", "TrickBot"]
      }
    }
  }
}
```

#### Enhanced Attribution Matrix
```json
{
  "case_id": "case-20251029-XXXX",
  "operator_hypothesis": {
    "confidence": 0.92,
    "hypothesis": "Eastern European cybercrime syndicate using bulletproof hosting",
    "evidence_count": 18
  },
  "intelligence_integrations": {
    "criminal_hunter": "bulletproof_hosting_detected",
    "infrastructure_mapper": "c2_infrastructure_mapped",
    "threat_intelligence": "multiple_feed_correlations",
    "enrich_last_hunt": "suspicious_ssl_certificates"
  },
  "pivots": [
    {
      "type": "criminal_infrastructure",
      "source": "criminal_hunter",
      "value": "bulletproof_hosting_pattern",
      "matches": ["current_campaign", "historical_campaigns"],
      "weight": 0.9
    },
    {
      "type": "threat_intel_correlation",
      "source": "virustotal_abuseipdb",
      "value": "high_abuse_scores",
      "matches": ["domain_1", "domain_2", "ip_ranges"],
      "weight": 0.85
    }
  ]
}
```

## 🚨 Sicurezza e Privacy

- **No Egress Default**: Nessuna connessione esterna senza `--anchor`
- **Evidence Preservation**: Timestamping crittografico opzionale
- **PII Handling**: Nessuna memorizzazione contenuti email
- **Key Management**: Chiavi private esterne, non nel codice

## 🤝 Contributing

PAW è open-source. Per contribuire:

1. Fork del repository
2. Crea feature branch
3. Aggiungi test per nuove funzionalità
4. Submit pull request

## 📄 Licenza

MIT License - vedere LICENSE file per dettagli.

## 🛡️ Policy Sicurezza e Network

### Isolamento di Rete
PAW implementa **defense-in-depth** per garantire analisi forense sicura senza compromettere la sicurezza del sistema.

#### Comandi Base (No Egress)
- **`trace`**: **Default no-egress**. Analizza solo contenuti locali, non contatta mai infrastruttura esterna
- **Input**: File `.eml`/`.msg` locali
- **Output**: Report forense completo senza connessioni di rete
- **Uso**: Analisi primaria, ambienti air-gapped

#### Comandi Avanzati (Egress Controllato)
- **`detonate`**: Egress osservativo con policy **observe-only**
  - ✅ GET/HEAD/OPTIONS permessi
  - ❌ POST/PUT/PATCH/DELETE bloccati
  - 📊 Logging completo di tutte le richieste
  - 🎯 Scopo: Mappare infrastruttura senza interagire

- **`detonate --encrypted`**: Egress interattivo crittografato
  - 🔐 Traffico crittografato end-to-end
  - 🎭 Simulazione interazioni phishing (form fill, navigation)
  - 📸 Screenshot crittografati
  - ⚠️ Richiede consenso esplicito per interazioni
  - 🌐 **Network Policy**: Allowlist egress verso host del caso + CDN trusted (fonts.googleapis.com, etc.)

- **`canary`**: Egress controllato per server passivo
  - 🌐 Solo porte specificate (default 8787)
  - 📝 Logging IP/UA visitatori
  - 🛡️ Firewall rules applicate automaticamente

### Controlli di Sicurezza
- **Network Isolation**: Container encrypted clicking con allowlist egress (non `network_mode: none`)
- **Resource Limits**: CPU ≤50%, RAM ≤512MB per processo
- **No Privileges**: Esecuzione senza root
- **Ephemeral Keys**: Chiavi crittografiche generate per sessione
- **Audit Logging**: Tracciamento completo operazioni

### Network Policy per Encrypted Clicking
L'encrypted clicking richiede **connettività controllata** per raggiungere i target phishing:

#### Allowlist Egress
```bash
# Host del caso (da URL estratti)
- *.bit.ly
- *.shorturl.at
- Target domain del phishing

# CDN/Fonti trusted (per rendering corretto)
- fonts.googleapis.com
- fonts.gstatic.com
- www.google-analytics.com
- www.googletagmanager.com

# Browser/CDN essenziali
- chromium.org
- *.cloudflare.com
```

#### Implementazione
```yaml
# docker-compose.encrypted-clicker.yml
services:
  encrypted-clicker:
    network_mode: bridge
    # NON network_mode: none
    environment:
      - ALLOWLIST_HOSTS=${CASE_HOSTS},fonts.googleapis.com,fonts.gstatic.com
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp
```

#### Alternative Sicure
1. **Proxy Recorder**: Traffico instradato attraverso proxy che logga tutto
2. **VPN Controllata**: Connessione attraverso VPN aziendale con logging
3. **Air-Gapped Analysis**: Upload risultati manualmente (non raccomandato)

### Raccomandazioni Operative
```bash
# Ambiente sicuro: sempre inizia con trace no-egress
python -m paw trace --src email.eml --no-egress

# Poi detona se necessario (ambiente controllato)
python -m paw detonate --case <case> --observe --pcap

# Encrypted clicking solo con consenso e in container isolato
python -m paw detonate --case <case> --encrypted --crypto-vault /secure/path
```

**⚠️ ATTENZIONE**: I comandi `detonate` e `canary` richiedono connessioni di rete controllate. Usa solo in ambienti sicuri con firewall configurato.
