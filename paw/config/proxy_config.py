# paw/config/proxy_config.py
"""
Proxy configuration for PAW security.
Configure your proxy settings here for safe external requests.
"""

import os

# Proxy Configuration
# Set your proxy URL here. Examples:
# - HTTP Proxy: "http://proxy.company.com:8080"
# - HTTPS Proxy: "https://proxy.company.com:8080"
# - SOCKS5 Proxy: "socks5://proxy.company.com:1080"
# - With authentication: "http://user:pass@proxy.company.com:8080"

# Default proxy URL (set via environment variable or directly here)
DEFAULT_PROXY_URL = os.environ.get('PAW_PROXY_URL', None)

# Alternative proxy configurations (uncomment the one you need):

# 🏢 CORPORATE PROXY
# DEFAULT_PROXY_URL = "http://proxy.corporate.com:8080"
# DEFAULT_PROXY_URL = "https://secure-proxy.company.com:8443"

# 🔓 FREE PROXY (Testing only - NOT for production!)
# DEFAULT_PROXY_URL = "http://190.103.177.131:80"  # Example free proxy
# DEFAULT_PROXY_URL = "http://154.16.202.22:3128"   # Another example

# 💰 PAID PROXY SERVICES (Recommended for production)
# DEFAULT_PROXY_URL = "http://user:pass@proxy.smartproxy.com:10000"  # SmartProxy
# DEFAULT_PROXY_URL = "http://user:pass@proxy.oxylabs.io:60000"       # Oxylabs
# DEFAULT_PROXY_URL = "http://user:pass@proxy.brightdata.com:22225"   # BrightData

# 🏠 LOCAL PROXY (if running local proxy server)
# DEFAULT_PROXY_URL = "http://localhost:8080"
# DEFAULT_PROXY_URL = "socks5://localhost:1080"

# No proxy (direct connection - NOT RECOMMENDED for security)
# DEFAULT_PROXY_URL = None

def get_proxy_config() -> dict:
    """Get proxy configuration for requests."""
    if not DEFAULT_PROXY_URL:
        return None

    return {
        'http': DEFAULT_PROXY_URL,
        'https': DEFAULT_PROXY_URL
    }

def setup_proxy_environment(proxy_url: str = None):
    """Setup proxy environment variable."""
    if proxy_url:
        os.environ['PAW_PROXY_URL'] = proxy_url
        print(f"✅ Proxy configurato: {proxy_url}")
    else:
        print("❌ Nessun proxy specificato")

def test_proxy_connection(proxy_url: str = None) -> bool:
    """Test proxy connection."""
    import requests
    from requests.exceptions import RequestException

    test_url = proxy_url or DEFAULT_PROXY_URL
    if not test_url:
        print("❌ Nessun proxy configurato per il test")
        return False

    try:
        proxies = {'http': test_url, 'https': test_url}
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
        if response.status_code == 200:
            print(f"✅ Proxy funzionante: {test_url}")
            return True
        else:
            print(f"❌ Proxy non risponde correttamente: {response.status_code}")
            return False
    except RequestException as e:
        print(f"❌ Errore connessione proxy: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Configurazione Proxy PAW")
    print("=" * 40)

    current_proxy = os.environ.get('PAW_PROXY_URL', 'NON IMPOSTATO')
    print(f"Proxy attuale: {current_proxy}")

    # Test current proxy if set
    if current_proxy and current_proxy != 'NON IMPOSTATO':
        print("\n🧪 Testando proxy attuale...")
        test_proxy_connection(current_proxy)

    print("\n📝 Per configurare un proxy:")
    print("1. Modifica DEFAULT_PROXY_URL in questo file")
    print("2. Oppure imposta la variabile d'ambiente: $env:PAW_PROXY_URL = 'http://tuo-proxy:porta'")
    print("3. Riavvia l'applicazione PAW")