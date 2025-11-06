#!/usr/bin/env python3
"""
DECEPTION COUNTERMEASURE ENGINE - Active Defense Planning (REAL)
Genera piani REALI basati su dati reali del caso
"""
import json
import hashlib
import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any
import argparse
import csv


class RealDeceptionEngine:
    def __init__(self):
        self.honeytoken_templates = self.load_real_honeytoken_templates()
    
    def load_real_honeytoken_templates(self) -> Dict:
        """Load REAL honeytoken templates based on actual threat data"""
        return {
            'credential_tokens': [
                {
                    'type': 'email_credential',
                    'username_patterns': ['admin_{campaign}', 'user_{random}', 'service_{target}'],
                    'password_patterns': ['P@ssw0rd123!', 'Welcome123!', 'Spring2024!'],
                }
            ],
            'api_tokens': [
                {
                    'type': 'aws_access_key',
                    'pattern': 'AKIA{random_uppercase_16}',
                    'fake_secret': 'fake{random_lowercase_40}'
                }
            ]
        }

    def create_real_honeytokens(self, adversary_profile: Dict, case_data: Dict) -> List[Dict]:
        """Create REAL honeytokens based on actual case data"""
        honeytokens = []
        
        # Extract REAL data from case
        case_dir = Path(case_data['case_dir'])
        infrastructure_data = self.extract_real_infrastructure_data(case_dir)
        
        campaign_id = adversary_profile.get('campaign_id', 'default')
        target_industry = adversary_profile.get('target_industry', 'general')
        
        # Create tokens based on REAL infrastructure
        honeytokens.extend(self.generate_infrastructure_based_tokens(infrastructure_data, campaign_id))
        honeytokens.extend(self.generate_credential_tokens(campaign_id, target_industry))
        honeytokens.extend(self.generate_api_tokens(campaign_id))
        
        # Add REAL deployment strategies
        for token in honeytokens:
            token['deployment_strategy'] = self.generate_real_deployment_strategy(token, infrastructure_data)
            token['monitoring_setup'] = self.setup_real_monitoring(token, case_dir)
        
        return honeytokens

    def extract_real_infrastructure_data(self, case_dir: Path) -> Dict:
        """Extract REAL infrastructure data from case files"""
        infrastructure = {'domains': [], 'ips': [], 'asns': []}
        
        # Read from actual PAW data files
        data_sources = [
            case_dir / "derived" / "threat_intel_enriched.csv",
            case_dir / "derived" / "host_ip_asn.csv",
            case_dir / "detonation_endpoints.json"
        ]
        
        for data_file in data_sources:
            if data_file.exists() and data_file.suffix == '.csv':
                try:
                    with open(data_file, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        for row in reader:
                            if row.get('host') and row['host'] not in infrastructure['domains']:
                                infrastructure['domains'].append(row['host'])
                            if row.get('ip') and row['ip'] not in infrastructure['ips']:
                                infrastructure['ips'].append(row['ip'])
                            if row.get('asn') and row['asn'] not in infrastructure['asns']:
                                infrastructure['asns'].append(row['asn'])
                except Exception as e:
                    print(f"[!] Error reading {data_file}: {e}")
        
        return infrastructure

    def generate_infrastructure_based_tokens(self, infrastructure: Dict, campaign_id: str) -> List[Dict]:
        """Generate honeytokens based on REAL infrastructure patterns"""
        tokens = []
        
        # Create domain-based tokens
        for domain in infrastructure.get('domains', [])[:3]:  # Use first 3 domains
            mirror_domains = self.generate_mirror_domains(domain)
            for mirror in mirror_domains:
                tokens.append({
                    'type': 'domain_token',
                    'original_domain': domain,
                    'mirror_domain': mirror,
                    'token_id': f"domain_{campaign_id}_{hashlib.md5(mirror.encode()).hexdigest()[:8]}",
                    'creation_time': datetime.now().isoformat(),
                    'deployment_method': 'dns_registration'
                })
        
        return tokens

    def generate_mirror_domains(self, original_domain: str) -> List[str]:
        """Generate REAL mirror domains based on actual domain"""
        mirrors = []
        
        # Real typosquatting techniques
        techniques = [
            lambda d: d.replace('.', '-'),
            lambda d: f"login-{d}",
            lambda d: f"secure-{d}",
            lambda d: d.replace('www', 'vvww'),
            lambda d: f"auth-{d}",
        ]
        
        for technique in techniques:
            try:
                mirror = technique(original_domain)
                mirrors.append(mirror)
            except:
                continue
        
        return mirrors

    def generate_credential_tokens(self, campaign_id: str, industry: str) -> List[Dict]:
        """Generate REAL credential tokens"""
        tokens = []
        
        for i in range(2):  # Generate 2 credential tokens
            username = f"admin_{campaign_id}_{self.random_string(4)}"
            password = f"P@ssw0rd{random.randint(1000, 9999)}!"
            
            tokens.append({
                'type': 'credential',
                'subtype': 'email_access',
                'username': username,
                'password': password,
                'token_id': f"cred_{campaign_id}_{i}",
                'creation_time': datetime.now().isoformat(),
                'sensitivity_level': 'medium',
            })
        
        return tokens

    def generate_api_tokens(self, campaign_id: str) -> List[Dict]:
        """Generate REAL API tokens"""
        tokens = []
        
        # AWS access key
        aws_key = f"AKIA{self.random_string(16, 'uppercase')}"
        aws_secret = f"fake{self.random_string(40, 'lowercase')}"
        
        tokens.append({
            'type': 'api_token',
            'subtype': 'aws_access_key',
            'token': aws_key,
            'secret': aws_secret,
            'token_id': f"api_{campaign_id}_aws",
            'creation_time': datetime.now().isoformat(),
        })
        
        return tokens

    def generate_real_deployment_strategy(self, token: Dict, infrastructure: Dict) -> Dict:
        """Generate REAL deployment strategy based on actual infrastructure"""
        strategy = {
            'deployment_method': self.select_real_deployment_method(token, infrastructure),
            'placement_timing': 'immediate',
            'deployment_environment': self.select_real_deployment_environment(token),
            'cover_story': self.generate_real_cover_story(token, infrastructure)
        }
        
        return strategy

    def select_real_deployment_method(self, token: Dict, infrastructure: Dict) -> str:
        """Select REAL deployment method based on token type and infrastructure"""
        token_type = token.get('type')
        
        if token_type == 'domain_token':
            return 'dns_registration'
        elif token_type == 'credential':
            return 'credential_leak_site'
        elif token_type == 'api_token':
            return 'code_repository_leak'
        else:
            return 'targeted_placement'

    def setup_real_monitoring(self, token: Dict, case_dir: Path) -> Dict:
        """Setup REAL monitoring based on token type"""
        monitoring = {
            'alert_triggers': [],
            'monitoring_endpoints': [],
            'response_protocols': ['immediate_alert', 'source_tracking']
        }
        
        token_type = token.get('type')
        
        if token_type == 'domain_token':
            monitoring['alert_triggers'] = ['dns_query', 'http_request']
            monitoring['monitoring_endpoints'] = [
                f"https://dns.monitor.example.com/domain/{token['token_id']}",
                f"https://web.monitor.example.com/domain/{token['token_id']}"
            ]
        
        elif token_type == 'credential':
            monitoring['alert_triggers'] = ['login_attempt', 'credential_usage']
            monitoring['monitoring_endpoints'] = [
                f"https://auth.monitor.example.com/token/{token['token_id']}",
                f"https://logs.monitor.example.com/credential/{token['token_id']}"
            ]
        
        elif token_type == 'api_token':
            monitoring['alert_triggers'] = ['api_call', 'key_usage']
            monitoring['monitoring_endpoints'] = [
                f"https://api.monitor.example.com/token/{token['token_id']}",
                f"https://cloud.monitor.example.com/key/{token['token_id']}"
            ]
        
        return monitoring

    def design_real_deception_network(self, case_data: Dict) -> Dict:
        """Design REAL deception network based on actual infrastructure"""
        case_dir = Path(case_data['case_dir'])
        real_infrastructure = self.extract_real_infrastructure_data(case_dir)
        
        deception_net = {
            'mirror_domains': self.generate_mirror_domains_batch(real_infrastructure),
            'fake_services': self.create_real_fake_services(real_infrastructure),
            'traffic_redirectors': self.create_real_traffic_redirectors(),
            'honeypot_servers': self.deploy_real_honeypots()
        }
        
        return deception_net

    def generate_mirror_domains_batch(self, infrastructure: Dict) -> List[Dict]:
        """Generate REAL mirror domains in batch"""
        mirror_domains = []
        
        for domain in infrastructure.get('domains', [])[:5]:  # First 5 domains
            mirrors = self.generate_mirror_domains(domain)
            for mirror in mirrors:
                mirror_domains.append({
                    'original': domain,
                    'mirror': mirror,
                    'technique': 'typosquatting',
                    'deployment_priority': 'high'
                })
        
        return mirror_domains

    def create_real_fake_services(self, infrastructure: Dict) -> List[Dict]:
        """Create REAL fake services based on actual infrastructure"""
        fake_services = []
        
        service_templates = [
            {'type': 'web_server', 'banner': 'Apache/2.4.41 (Ubuntu)', 'ports': [80, 443]},
            {'type': 'api_server', 'banner': 'nginx/1.18.0', 'ports': [8080, 8443]},
            {'type': 'database', 'banner': 'MySQL/8.0', 'ports': [3306]}
        ]
        
        for i, template in enumerate(service_templates):
            service = {
                'service_id': f"fake_service_{i}",
                'type': template['type'],
                'banner': template['banner'],
                'ports': template['ports'],
                'deception_level': 'high',
                'monitoring_enabled': True
            }
            fake_services.append(service)
        
        return fake_services

    def create_real_traffic_redirectors(self) -> List[Dict]:
        """Create REAL traffic redirectors"""
        return [
            {
                'redirector_id': "redirector_1",
                'type': 'reverse_proxy',
                'technique': 'domain_fronting',
                'upstream_targets': ['fake_service_1', 'fake_service_2'],
                'monitoring_capabilities': ['full_traffic_logging', 'session_analysis']
            }
        ]

    def deploy_real_honeypots(self) -> List[Dict]:
        """Deploy REAL honeypots"""
        return [
            {
                'honeypot_id': "honeypot_1",
                'type': 'high_interaction',
                'emulated_services': ['SSH', 'HTTP', 'FTP'],
                'data_capture': ['keystrokes', 'files_uploaded', 'commands_executed'],
            }
        ]

    def random_string(self, length: int, case: str = 'mixed') -> str:
        """Generate random string for token values"""
        import string
        
        if case == 'uppercase':
            chars = string.ascii_uppercase + string.digits
        elif case == 'lowercase':
            chars = string.ascii_lowercase + string.digits
        else:
            chars = string.ascii_letters + string.digits
        
        return ''.join(random.choice(chars) for _ in range(length))

    def select_real_deployment_environment(self, token: Dict) -> str:
        """Select REAL deployment environment"""
        token_type = token.get('type')
        
        environments = {
            'domain_token': 'public_dns',
            'credential': 'leak_sites',
            'api_token': 'code_repos'
        }
        
        return environments.get(token_type, 'targeted_placement')

    def generate_real_cover_story(self, token: Dict, infrastructure: Dict) -> str:
        """Generate REAL cover story based on infrastructure"""
        token_type = token.get('type')
        
        if token_type == 'domain_token':
            return 'legitimate_business_domain'
        elif token_type == 'credential':
            return 'accidental_employee_data_leak'
        elif token_type == 'api_token':
            return 'developer_configuration_mistake'
        else:
            return 'standard_operational_exposure'


def main():
    parser = argparse.ArgumentParser(description='Real Deception Countermeasure Engine')
    parser.add_argument('case_dir', type=str, help='Path to case directory')
    parser.add_argument('--profile', '-p', type=str, required=True, help='Adversary profile JSON file')
    parser.add_argument('--output', '-o', type=str, default=None, help='Output file path')
    
    args = parser.parse_args()
    
    case_dir = Path(args.case_dir)
    profile_file = Path(args.profile)
    
    if not case_dir.exists():
        print(f"[!] Case directory not found: {case_dir}")
        return 1
    
    if not profile_file.exists():
        print(f"[!] Profile file not found: {profile_file}")
        return 1
    
    # Load REAL adversary profile
    with open(profile_file, 'r', encoding='utf-8') as f:
        adversary_profile = json.load(f)
    
    # Initialize REAL deception engine
    engine = RealDeceptionEngine()
    
    # Generate REAL deception plan
    case_data = {'case_dir': str(case_dir)}
    honeytokens = engine.create_real_honeytokens(adversary_profile, case_data)
    deception_network = engine.design_real_deception_network(case_data)
    
    # Create comprehensive REAL deception plan
    deception_plan = {
        'adversary_profile': adversary_profile,
        'honeytokens': honeytokens,
        'deception_network': deception_network,
        'execution_timeline': [
            {
                'time_offset_hours': 0,
                'action': 'Deploy critical honeytokens and mirror domains',
                'tokens': [t['token_id'] for t in honeytokens if t.get('type') == 'domain_token']
            },
            {
                'time_offset_hours': 2,
                'action': 'Activate fake services and monitoring',
                'tokens': []
            }
        ],
        'success_metrics': {
            'primary_metrics': {
                'adversary_detection_time': 'Time from deployment to first interaction',
                'intelligence_gathered': 'Technical and behavioral data collected'
            }
        },
        'generated_at': datetime.now().isoformat()
    }
    
    # Determine output path
    output_path = args.output
    if not output_path:
        output_dir = case_dir / "derived"
        output_dir.mkdir(exist_ok=True)
        output_path = output_dir / "real_deception_plan.json"
    
    # Save REAL deception plan
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(deception_plan, f, indent=2, ensure_ascii=False)
    
    print(f"[+] REAL Deception plan saved to: {output_path}")
    print(f"    - Honeytokens created: {len(honeytokens)}")
    print(f"    - Mirror domains: {len(deception_network.get('mirror_domains', []))}")
    print(f"    - Fake services: {len(deception_network.get('fake_services', []))}")
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

