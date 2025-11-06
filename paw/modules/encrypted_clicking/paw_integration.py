# paw_integration.py - Integrazione del modulo encrypted clicking con PAW
import docker
import json
import os
import tempfile
import subprocess
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

class PAWEncryptedClicking:
    def __init__(self):
        self.docker_client = None
        self.container_image = "paw-encrypted-clicker:latest"
        self.cases_dir = os.path.join(os.getcwd(), "cases")
        os.makedirs(self.cases_dir, exist_ok=True)

    def _get_docker_client(self):
        """Get Docker client lazily"""
        if self.docker_client is None:
            try:
                import docker
                self.docker_client = docker.from_env()
            except Exception as e:
                logger.error(f"Errore inizializzazione Docker: {e}")
                raise
        return self.docker_client

    def build_clicker_image(self):
        """Costruisce l'immagine Docker per il clicking crittografato"""
        try:
            logger.info("Costruzione immagine Docker per encrypted clicking...")

            dockerfile_content = """FROM selenium/standalone-chrome:latest
RUN apt-get update && apt-get install -y \\
    python3-pip \\
    openssl \\
    cryptsetup \\
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY encrypted_clicker.py .
COPY paw_integration.py .
RUN mkdir -p /encrypted_storage
VOLUME /encrypted_storage
COPY init_crypto.sh .
RUN chmod +x init_crypto.sh
CMD ["./init_crypto.sh"]"""

            # Scrivi Dockerfile temporaneo
            with tempfile.NamedTemporaryFile(mode='w', suffix='.dockerfile', delete=False) as f:
                f.write(dockerfile_content)
                dockerfile_path = f.name

            # Costruisci immagine
            self._get_docker_client().images.build(
                path=os.path.dirname(__file__),
                dockerfile=dockerfile_path,
                tag=self.container_image,
                rm=True
            )

            # Pulisci file temporaneo
            os.unlink(dockerfile_path)

            logger.info("Immagine Docker costruita con successo")
            return True

        except Exception as e:
            logger.error(f"Errore costruzione immagine: {e}")
            return False

    def analyze_url_safely(self, url: str, case_id: str, enable_js: bool = False,
                          interaction_script: Optional[List[Dict]] = None) -> Dict[str, Any]:
        """Analizza URL in container Docker crittografato"""
        try:
            logger.info(f"Avvio analisi crittografata per URL: {url}")

            # Prepara script di interazione
            interactions_json = json.dumps(interaction_script) if interaction_script else "null"

            # Directory per il caso
            case_dir = os.path.join(self.cases_dir, case_id)
            os.makedirs(case_dir, exist_ok=True)

            # Genera password crittografica per la sessione
            crypto_password = self.generate_session_password(case_id)

            # Comando da eseguire nel container
            command = [
                "python3", "-c",
                f"""
import sys
sys.path.append('/app')
from encrypted_clicker import EncryptedClickAnalyzer
import json

analyzer = EncryptedClickAnalyzer()
result = analyzer.analyze_url_encrypted('{url}', {interactions_json}, {str(enable_js).lower()})
print(result)
"""
            ]

            # Esegui container
            container = self._get_docker_client().containers.run(
                self.container_image,
                command,
                detach=True,
                volumes={
                    case_dir: {'bind': '/mnt/crypto_vault', 'mode': 'rw'}
                },
                environment={
                    'CRYPTO_PASSWORD': crypto_password,
                    'PYTHONPATH': '/app'
                },
                network_mode='none',  # Isolamento di rete completo
                mem_limit='512m',     # Limite memoria
                cpu_period=100000,
                cpu_quota=50000,      # Limite CPU 50%
                remove=True            # Auto-rimuovi container
            )

            # Attendi completamento
            result = container.wait(timeout=300)  # 5 minuti timeout
            logs = container.logs()

            if result['StatusCode'] == 0:
                encrypted_result = logs.decode().strip()
                return self.process_encrypted_results(encrypted_result, case_id, crypto_password)
            else:
                error_msg = logs.decode()
                logger.error(f"Container execution failed: {error_msg}")
                return {'error': f'Container execution failed: {error_msg}'}

        except Exception as e:
            logger.error(f"Errore analisi URL: {e}")
            return {'error': str(e)}

    def generate_session_password(self, case_id: str) -> str:
        """Genera password crittografica per la sessione basata sul case ID"""
        import hashlib
        import secrets

        # Combina case_id con salt casuale per questa sessione
        salt = secrets.token_hex(16)
        combined = f"{case_id}_{salt}_{datetime.utcnow().isoformat()}"

        # Genera hash sicuro
        password = hashlib.sha256(combined.encode()).hexdigest()
        return password

    def process_encrypted_results(self, encrypted_logs: str, case_id: str, crypto_password: str) -> Dict[str, Any]:
        """Processa e decrittografa i risultati"""
        try:
            # I log dovrebbero contenere il risultato crittografato
            encrypted_data = encrypted_logs.strip()

            # Per decrittografare, dovremmo avere la stessa chiave di sessione
            # In produzione, questo richiederebbe un keystore sicuro
            # Per ora, restituiamo i metadati dell'analisi

            case_dir = os.path.join(self.cases_dir, case_id)
            analysis_files = [f for f in os.listdir(case_dir) if f.endswith('.enc')]

            if analysis_files:
                latest_file = max(analysis_files, key=lambda x: os.path.getctime(os.path.join(case_dir, x)))
                with open(os.path.join(case_dir, latest_file), 'r') as f:
                    metadata = json.load(f)

                return {
                    'status': 'success',
                    'case_id': case_id,
                    'analysis_file': latest_file,
                    'encrypted_result': encrypted_data,
                    'metadata': metadata,
                    'processing_timestamp': datetime.utcnow().isoformat()
                }
            else:
                return {
                    'status': 'success',
                    'case_id': case_id,
                    'encrypted_result': encrypted_data,
                    'processing_timestamp': datetime.utcnow().isoformat()
                }

        except Exception as e:
            logger.error(f"Errore processamento risultati: {e}")
            return {'error': f"Processing failed: {str(e)}"}

    def generate_interaction_script(self, url: str, phishing_type: str = "generic") -> List[Dict]:
        """Genera script di interazione basato su euristiche di phishing"""
        base_interactions = []

        if phishing_type == "credential_harvesting":
            base_interactions = [
                {'type': 'wait', 'seconds': 3},
                {'type': 'form_fill', 'selector': 'input[type="email"], input[name*="email"]', 'data': 'test@example.com'},
                {'type': 'form_fill', 'selector': 'input[type="password"], input[name*="pass"]', 'data': 'testpassword123'},
                {'type': 'click', 'selector': 'button[type="submit"], input[type="submit"]'},
                {'type': 'wait', 'seconds': 2}
            ]
        elif phishing_type == "banking":
            base_interactions = [
                {'type': 'wait', 'seconds': 2},
                {'type': 'form_fill', 'selector': 'input[name*="account"], input[name*="user"]', 'data': '123456789'},
                {'type': 'form_fill', 'selector': 'input[type="password"]', 'data': 'securepass123'},
                {'type': 'click', 'selector': 'button[type="submit"]'},
                {'type': 'wait', 'seconds': 3}
            ]
        else:  # generic
            base_interactions = [
                {'type': 'wait', 'seconds': 2},
                {'type': 'click', 'selector': 'a, button, input[type="submit"]'},
                {'type': 'wait', 'seconds': 1},
                {'type': 'form_fill', 'selector': 'input[type="text"], input[type="email"]', 'data': 'test@example.com'},
                {'type': 'click', 'selector': 'button[type="submit"], input[type="submit"]'},
                {'type': 'wait', 'seconds': 2}
            ]

        return base_interactions

    def decrypt_analysis_results(self, case_id: str, analysis_file: str) -> Optional[Dict]:
        """Decrittografa risultati di analisi (richiede chiave di sessione)"""
        try:
            case_dir = os.path.join(self.cases_dir, case_id)
            filepath = os.path.join(case_dir, analysis_file)

            with open(filepath, 'r') as f:
                metadata = json.load(f)

            # In produzione, recuperare chiave dal keystore sicuro
            # Per ora, restituiamo i metadati
            return metadata

        except Exception as e:
            logger.error(f"Errore decrittografia: {e}")
            return None

    def enhance_scoring_with_click_analysis(self, decrypted_analysis: Dict, case_id: str) -> Dict:
        """Migliora scoring PAW con dati dell'analisi clicking"""
        enhanced_score = {
            'original_score': 0,  # Dovrebbe venire da PAW esistente
            'click_analysis_bonus': 0,
            'indicators': []
        }

        try:
            # Analizza risultati per indicatori di rischio
            if 'security_indicators' in decrypted_analysis:
                sec_indicators = decrypted_analysis['security_indicators']

                if sec_indicators.get('has_password_fields'):
                    enhanced_score['click_analysis_bonus'] += 20
                    enhanced_score['indicators'].append('password_fields_detected')

                if sec_indicators.get('has_credit_card_fields'):
                    enhanced_score['click_analysis_bonus'] += 30
                    enhanced_score['indicators'].append('credit_card_fields_detected')

                if sec_indicators.get('has_login_forms'):
                    enhanced_score['click_analysis_bonus'] += 15
                    enhanced_score['indicators'].append('login_form_detected')

                if sec_indicators.get('has_suspicious_keywords'):
                    enhanced_score['click_analysis_bonus'] += 10
                    enhanced_score['indicators'].append('suspicious_keywords')

            # Analizza network requests
            if 'network_requests' in decrypted_analysis and len(decrypted_analysis['network_requests']) > 0:
                enhanced_score['click_analysis_bonus'] += 5
                enhanced_score['indicators'].append('network_activity_detected')

            # Analizza redirect chain
            if 'security_indicators' in decrypted_analysis:
                redirect_chain = decrypted_analysis['security_indicators'].get('redirect_chain', [])
                if len(redirect_chain) > 1:
                    enhanced_score['click_analysis_bonus'] += 10
                    enhanced_score['indicators'].append('redirect_chain_detected')

        except Exception as e:
            logger.error(f"Errore enhancement scoring: {e}")

        enhanced_score['final_score'] = enhanced_score['original_score'] + enhanced_score['click_analysis_bonus']
        return enhanced_score

def main():
    """CLI per testing del modulo"""
    import argparse

    parser = argparse.ArgumentParser(description='PAW Encrypted Clicking Module')
    parser.add_argument('url', help='URL da analizzare')
    parser.add_argument('--case-id', default='test_case', help='ID del caso')
    parser.add_argument('--build', action='store_true', help='Costruisci immagine Docker')
    parser.add_argument('--js', action='store_true', help='Abilita JavaScript')
    parser.add_argument('--phishing-type', choices=['generic', 'credential_harvesting', 'banking'],
                       default='generic', help='Tipo di phishing per script interazione')

    args = parser.parse_args()

    paw_clicker = PAWEncryptedClicking()

    if args.build:
        success = paw_clicker.build_clicker_image()
        if not success:
            exit(1)

    # Genera script interazione
    interaction_script = paw_clicker.generate_interaction_script(args.url, args.phishing_type)

    # Esegui analisi
    result = paw_clicker.analyze_url_safely(args.url, args.case_id, args.js, interaction_script)

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()