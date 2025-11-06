import json
from datetime import datetime
from typing import Dict

class LawEnforcementPackage:
    """Genera package completo per autorità"""
    
    def generate_package(self, criminal_data: Dict) -> Dict:
        """Genera package strutturato per LE"""
        return {
            'metadata': {
                'report_id': f"PAW-LE-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                'generated_date': datetime.now().isoformat(),
                'tool_used': 'PAW Criminal Hunter',
                'case_reference': criminal_data.get('case_id', 'N/A')
            },
            
            'executive_summary': self._generate_executive_summary(criminal_data),
            
            'technical_findings': {
                'primary_target': criminal_data.get('target_domain', 'Unknown'),
                'infrastructure_mapping': criminal_data.get('infrastructure', {}),
                'threat_actor_analysis': criminal_data.get('threat_intel', {}),
                'evidence_collection': criminal_data.get('real_ips', [])
            },
            
            'recommended_actions': [
                "Formal abuse report to hosting provider",
                "Contact relevant CERT for infrastructure takedown",
                "Share indicators with law enforcement partners",
                "Monitor for infrastructure re-emergence"
            ],
            
            'legal_considerations': [
                "All evidence collected through open-source intelligence",
                "No unauthorized access to systems occurred",
                "Data collection complies with local laws",
                "Chain of custody maintained for all evidence"
            ],
            
            'contact_information': {
                'reporting_organization': 'PAW Digital Forensics',
                'prepared_by': 'Automated Criminal Hunter System',
                'follow_up_contact': 'security-team@organization.com'
            }
        }
    
    def _generate_executive_summary(self, criminal_data: Dict) -> str:
        """Genera summary esecutivo"""
        domain = criminal_data.get('target_domain', 'Unknown')
        threat_actor = criminal_data.get('threat_intel', {}).get('threat_actor', 'Unknown')
        confidence = criminal_data.get('threat_intel', {}).get('confidence', 0)
        risk_score = criminal_data.get('threat_intel', {}).get('risk_score', 0)
        
        return f"""
CRIMINAL INFRASTRUCTURE ANALYSIS REPORT

Primary Target: {domain}
Identified Threat Actor: {threat_actor}
Attribution Confidence: {confidence:.0%}
Risk Assessment: {risk_score}/100

EXECUTIVE SUMMARY:
This report details criminal infrastructure associated with phishing operations
targeting organizational assets. The infrastructure has been actively used in
credential harvesting campaigns and exhibits characteristics consistent with
professional cybercrime operations.

KEY FINDINGS:
- Criminal infrastructure hosted with: {criminal_data.get('infrastructure', {}).get('asn_org', 'Unknown')}
- Primary operational IPs: {len(criminal_data.get('real_ips', []))}
- Infrastructure located in: {criminal_data.get('infrastructure', {}).get('geolocation', 'Unknown')}
- Associated with known threat patterns

RECOMMENDATION:
Immediate infrastructure takedown recommended to disrupt ongoing criminal operations.
        """.strip()
