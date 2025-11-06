#!/bin/bash
# init_crypto.sh - Inizializzazione ambiente crittografato

set -e

echo "=== Inizializzazione Ambiente Crittografato PAW ==="

# Genera chiavi ephemeral per la sessione
echo "Generazione chiavi di sessione..."
openssl genrsa -out /tmp/session_key.pem 4096 2>/dev/null
openssl rsa -in /tmp/session_key.pem -pubout -out /tmp/session_pub.pem 2>/dev/null

# Crea filesystem crittografato per storage
echo "Creazione vault crittografato..."
sudo dd if=/dev/zero of=/encrypted_storage/vault.img bs=1M count=100 2>/dev/null
echo "${CRYPTO_PASSWORD:-default_session_key}" | sudo cryptsetup luksFormat /encrypted_storage/vault.img --key-file=-
echo "${CRYPTO_PASSWORD:-default_session_key}" | sudo cryptsetup open /encrypted_storage/vault.img crypto_vault --key-file=-
sudo mkfs.ext4 /dev/mapper/crypto_vault 2>/dev/null
sudo mount /dev/mapper/crypto_vault /mnt/crypto_vault
sudo chown -R seluser:seluser /mnt/crypto_vault

echo "Vault crittografato inizializzato con successo"

# Avvia il modulo di clicking
echo "Avvio modulo di clicking crittografato..."
exec python3 /app/encrypted_clicker.py