# PAW Sentinel - File Monitoring Infrastructure
# Monitoraggio continuo dell'integrità dei file di analisi

## 📊 COSA MONITORA IL SISTEMA:

### File Analizzati per Caso:
- **input.eml** - Email originale analizzata
- **manifest.json** - Metadati del caso
- **evidence/** - File di prova crittografica
  - `merkle_index.json` - Indice dei file con hash
  - `merkle_root.bin` - Radice Merkle per verifica integrità
- **report/** - Report generati (HTML, PDF, etc.)
- **graphs/** - Grafici e visualizzazioni
- **canary/** - Log delle interazioni canary
- **detonation/** - Risultati della detonazione

### Tipi di Monitoraggio:
1. **🔐 Integrità Crittografica** - Verifica Merkle root
2. **📁 Cambiamenti File** - Rilevamento nuovi/modificati/eliminati
3. **⏰ Monitoraggio Temporale** - Alert periodici
4. **🚨 Alert Automatici** - Notifiche per problemi

## 🏗️ INFRASTRUTTURA RICHIESTA:

### Componenti Core:
```
PAW Sentinel
├── monitor.py          # Monitor URL campagne
├── file_monitor.py     # Monitor integrità file
├── database.py         # Database SQLite condiviso
└── config.py           # Configurazione unificata
```

### Database Estensioni:
```sql
-- Tabella esistente campaigns
-- NUOVA: file_integrity_checks
CREATE TABLE file_integrity_checks (
    id INTEGER PRIMARY KEY,
    case_id TEXT NOT NULL,
    check_time TEXT NOT NULL,
    integrity_status TEXT,  -- 'ok', 'compromised', 'unknown'
    merkle_match BOOLEAN,
    files_count INTEGER,
    changes_detected TEXT,  -- JSON con cambiamenti
    FOREIGN KEY (case_id) REFERENCES campaigns(case_id)
);
```

### Scheduler Automatico:
- **Cron jobs** per controlli periodici
- **Systemd timers** per monitoraggio continuo
- **Webhook** per alert in tempo reale

## 🚀 COME USARE IL MONITORAGGIO FILE:

### Controlli Base:
```bash
# Verifica integrità di tutti i casi
paw monitor integrity

# Rileva cambiamenti nei file
paw monitor files

# Controllo specifico di un caso
paw monitor files --case case-2025-10-29T233028Z-6dd0
```

### Automazione:
```bash
# Controllo giornaliero (aggiungi a crontab)
0 2 * * * cd /path/to/paw && paw monitor integrity > integrity_report.txt

# Monitoraggio continuo con alert
paw monitor start  # Include ora anche file monitoring
```

## 📈 VANTAGGI DELL'INFRASTRUTTURA:

### Sicurezza:
- **Rilevamento Manomissioni** - File modificati vengono identificati
- **Audit Trail** - Storico completo dei cambiamenti
- **Backup Automatici** - Alert quando l'integrità è compromessa

### Operatività:
- **Monitoraggio Proattivo** - Problemi rilevati prima che diventino critici
- **Report Automatici** - Documentazione dello stato dei casi
- **Integrazione CI/CD** - Verifiche automatiche nei pipeline

### Scalabilità:
- **Database Condiviso** - URL e file monitoring in un'unica soluzione
- **Configurazione Unificata** - Parametri comuni per tutti i monitor
- **API Estensibile** - Facile aggiungere nuovi tipi di monitoraggio

## 🔧 IMPLEMENTAZIONE STEP-BY-STEP:

### Fase 1: Infrastruttura Base ✅
- [x] Classe FileMonitor implementata
- [x] Integrazione con CLI paw monitor
- [x] Verifica integrità Merkle esistente

### Fase 2: Database Integration 🔄
- [ ] Estendere CampaignDatabase per file monitoring
- [ ] Aggiungere tabella file_integrity_checks
- [ ] Storico cambiamenti nel tempo

### Fase 3: Automazione 🚀
- [ ] Scheduler per controlli automatici
- [ ] Alert system integrato
- [ ] Dashboard web per monitoraggio

### Fase 4: Advanced Features 💡
- [ ] Backup automatico quando integrità compromessa
- [ ] Notifiche email/Slack per alert
- [ ] Analisi trend dei cambiamenti

## 🎯 RISULTATI ATTESI:

Con questa infrastruttura, PAW diventa un sistema completo di:
- **Analisi Forense** - Tracciamento campagne phishing
- **Monitoraggio Continuo** - Vigilanza attiva delle minacce
- **Protezione Integrità** - Garanzia che le evidenze rimangano intatte
- **Audit Compliance** - Tracciabilità completa delle operazioni

Il sistema trasforma PAW da strumento reattivo ad infrastruttura proattiva di difesa cibernetica! 🛡️</content>
<parameter name="filePath">c:\Users\dacan\OneDrive\Desktop\SentinelV1_paw\PAW\FILE_MONITORING_INFRASTRUCTURE.md