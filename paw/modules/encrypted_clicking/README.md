# PAW Encrypted Clicking Module

Modulo containerizzato per analisi sicura e crittografata di URL sospetti attraverso browser automation.

## 🚀 Installazione Rapida

```bash
# Installa dipendenze
pip install -r requirements.txt

# Build immagine Docker
docker build -t paw-encrypted-clicker -f Dockerfile.encrypted .

# Test funzionamento
python paw_integration.py --help
```

## 📋 Prerequisiti

- Docker Engine
- Python 3.8+
- 1GB RAM disponibile (container limitato a 512MB)
- Connessione internet per build iniziale

## 🎯 Utilizzo Base

### Analisi URL Singola
```bash
python paw_integration.py https://suspicious-site.com --case-id test_001
```

### Con Opzioni Avanzate
```bash
# Abilita JavaScript
python paw_integration.py https://site.com --js --case-id test_002

# Tipo specifico di phishing
python paw_integration.py https://bank.com --phishing-type banking --case-id bank_test

# Build immagine prima dell'uso
python paw_integration.py https://site.com --build --case-id built_test
```

## 🏗️ Architettura

```
paw/modules/encrypted_clicking/
├── Dockerfile.encrypted          # Immagine container sicura
├── init_crypto.sh               # Inizializzazione crittografia
├── encrypted_clicker.py         # Core analyzer con Selenium
├── paw_integration.py           # Integrazione PAW
├── requirements.txt             # Dipendenze Python
└── docker-compose.encrypted-clicker.yml  # Deployment orchestrato
```

## 🔐 Sicurezza

- **Crittografia AES-256**: Tutti i dati crittografati end-to-end
- **Isolamento Container**: Nessun accesso alla rete host
- **Ephemeral Keys**: Chiavi generate per ogni sessione
- **Resource Limits**: CPU/Memoria limitati per prevenzione abusi
- **No Persistence**: Dati eliminati dopo analisi

## 📊 Output

I risultati vengono salvati in `cases/{case_id}/` come file `.enc` crittografati:

```json
{
  "status": "success",
  "case_id": "test_001",
  "analysis_file": "analysis_20251029_143052.enc",
  "encrypted_result": "gAAAAAB...",
  "metadata": {
    "original_url": "https://suspicious-site.com",
    "analysis_date": "2025-10-29T14:30:52.123456",
    "analyzer_version": "1.0.0"
  }
}
```

## 🔧 Troubleshooting

### Errore Build Docker
```bash
# Verifica Docker installato
docker --version

# Build con BuildKit (raccomandato)
DOCKER_BUILDKIT=1 docker build -t paw-encrypted-clicker -f Dockerfile.encrypted .
```

### Errore Connessione Container
```bash
# Verifica rete Docker
docker network ls

# Test container base
docker run --rm selenium/standalone-chrome:latest echo "OK"
```

### Problemi Memoria
```bash
# Aumenta limite memoria Docker Desktop
# Oppure riduci concorrenza nell'analisi
```

## 🤝 Integrazione PAW

Il modulo si integra automaticamente con il sistema di scoring PAW:

```bash
# Analizza email con clicking crittografato
python -m paw trace --src phishing.eml --encrypted-click --case-id auto_001

# Risultati integrati nello scoring finale
# +35 per campi password, +25 per carte di credito, etc.
```

## 📈 Metriche Sicurezza

- **Isolamento**: Container con network none
- **Crittografia**: AES-256 con PBKDF2 key derivation
- **Audit**: Logging completo operazioni
- **Limits**: CPU 50%, RAM 512MB, no privileged access

## 🚨 Note Sicurezza

- **Non eseguire in produzione** senza test approfonditi
- **Isolamento di rete**: Container non deve accedere alla rete interna
- **Monitoraggio risorse**: Limiti stretti per prevenzione abusi
- **Data handling**: Tutti i dati crittografati, nessuna persistenza non crittografata