# Sentinel - Continuous Phishing Campaign Monitoring

Sentinel è il modulo di monitoraggio continuo di PAW che permette di tracciare attivamente le campagne di phishing nel tempo.

## Funzionalità

- **Monitoraggio Continuo**: Controlla regolarmente lo stato delle campagne
- **Rilevamento Cambiamenti**: Identifica modifiche al contenuto delle pagine
- **Screenshot Automatici**: Cattura immagini delle pagine nel tempo
- **Sistema di Alert**: Notifiche per eventi importanti
- **Database Integrato**: SQLite per storage locale dei dati
- **🆕 Monitoraggio File**: Verifica integrità dei file di analisi PAW
- **🆕 Alert Atomici**: Email automatiche quando vittime cliccano phishing

## Comandi CLI

### Monitoraggio Campagne URL
```bash
paw monitor add --case "case-2025-10-29T233028Z-6dd0" --url "https://example.com/phish"
paw monitor status
paw monitor check                    # Tutte le campagne
paw monitor check --campaign ID     # Campagna specifica
paw monitor list                    # Lista campagne attive
paw monitor remove --case CASE_ID   # Rimuovi campagna
```

### 🆕 Monitoraggio Integrità File
```bash
paw monitor integrity               # Report integrità di tutti i casi
paw monitor files                   # Rileva cambiamenti nei file
```

### Controllo e Gestione
```bash
paw monitor start                   # Avvia monitoraggio continuo
paw monitor stop                    # Ferma monitoraggio
```

## Configurazione

Il modulo usa `sentinel_config.json` per la configurazione:

```json
{
  "monitoring": {
    "check_interval_minutes": 30,
    "max_concurrent_checks": 5,
    "timeout_seconds": 30
  },
  "alerts": {
    "enabled": true,
    "alert_on_changes": true,
    "alert_on_down": true
  }
}
```

## Architettura

- **config.py**: Gestione configurazione
- **database.py**: Database SQLite per campagne e controlli
- **monitor.py**: Core engine di monitoraggio

## Prossimi Sviluppi

- Dashboard web per visualizzazione real-time
- Integrazione con sistemi SIEM
- Alert webhook per notifiche esterne
- Analisi predittiva dei cambiamenti