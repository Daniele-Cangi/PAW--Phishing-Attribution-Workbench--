#!/bin/bash
# PAW v2.0 Deployment Script
# Automated deployment with security checks

set -e  # Exit on error

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}PAW v2.0 Deployment Script${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo -e "${RED}ERROR: Do not run as root!${NC}"
    exit 1
fi

# Check dependencies
echo -e "\n${YELLOW}[1/10] Checking dependencies...${NC}"
command -v python3 >/dev/null 2>&1 || { echo -e "${RED}ERROR: python3 not found${NC}"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo -e "${RED}ERROR: docker not found${NC}"; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo -e "${RED}ERROR: docker-compose not found${NC}"; exit 1; }
echo -e "${GREEN}✓ Dependencies OK${NC}"

# Check Python version
echo -e "\n${YELLOW}[2/10] Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
REQUIRED_VERSION="3.8"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}ERROR: Python >= 3.8 required, found $PYTHON_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION OK${NC}"

# Check .env file
echo -e "\n${YELLOW}[3/10] Checking configuration...${NC}"
if [ ! -f .env ]; then
    echo -e "${YELLOW}WARNING: .env not found, copying from .env.example${NC}"
    cp .env.example .env
    echo -e "${RED}REQUIRED: Edit .env and configure CRYPTO_PASSWORD!${NC}"
    echo -e "${YELLOW}Generate password: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'${NC}"
    exit 1
fi

# Validate CRYPTO_PASSWORD is set
source .env
if [ -z "$CRYPTO_PASSWORD" ]; then
    echo -e "${RED}ERROR: CRYPTO_PASSWORD not set in .env${NC}"
    echo -e "${YELLOW}Generate: python3 -c 'import secrets; print(secrets.token_urlsafe(32))'${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Configuration OK${NC}"

# Create required directories
echo -e "\n${YELLOW}[4/10] Creating directories...${NC}"
mkdir -p vault
mkdir -p cases
mkdir -p logs
mkdir -p tests/unit tests/integration tests/fixtures
echo -e "${GREEN}✓ Directories created${NC}"

# Install Python dependencies
echo -e "\n${YELLOW}[5/10] Installing Python dependencies...${NC}"
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Install PAW package
echo -e "\n${YELLOW}[6/10] Installing PAW package...${NC}"
pip install -e .
echo -e "${GREEN}✓ PAW package installed${NC}"

# Run security audit
echo -e "\n${YELLOW}[7/10] Running security audit...${NC}"
echo -e "${YELLOW}Installing security tools...${NC}"
pip install bandit safety

echo -e "${YELLOW}Running Bandit (code security scanner)...${NC}"
bandit -r paw/ -f json -o security_audit.json 2>/dev/null || {
    echo -e "${YELLOW}WARNING: Some security issues found (check security_audit.json)${NC}"
}

echo -e "${YELLOW}Running Safety (dependency vulnerability scanner)...${NC}"
safety check -r requirements.txt --json --output safety_audit.json 2>/dev/null || {
    echo -e "${YELLOW}WARNING: Some vulnerable dependencies found (check safety_audit.json)${NC}"
}
echo -e "${GREEN}✓ Security audit completed${NC}"

# Build Docker image
echo -e "\n${YELLOW}[8/10] Building Docker image...${NC}"
docker-compose build
echo -e "${GREEN}✓ Docker image built${NC}"

# Test Docker image
echo -e "\n${YELLOW}[9/10] Testing Docker image...${NC}"
docker-compose run --rm paw-analyzer python -c "from paw.modules.encrypted_clicking.encrypted_clicker import EncryptedClickAnalyzer; print('OK')" || {
    echo -e "${RED}ERROR: Docker image test failed${NC}"
    exit 1
}
echo -e "${GREEN}✓ Docker image test passed${NC}"

# Run tests
echo -e "\n${YELLOW}[10/10] Running tests...${NC}"
echo -e "${YELLOW}Installing test dependencies...${NC}"
pip install pytest pytest-cov pytest-asyncio

if [ -d "tests/unit" ] && [ "$(ls -A tests/unit/*.py 2>/dev/null)" ]; then
    echo -e "${YELLOW}Running unit tests...${NC}"
    pytest tests/unit/ -v --cov=paw --cov-report=html --cov-report=term-missing || {
        echo -e "${YELLOW}WARNING: Some tests failed${NC}"
    }
else
    echo -e "${YELLOW}WARNING: No unit tests found, skipping${NC}"
fi

# Deployment summary
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo -e "\n${YELLOW}Configuration Summary:${NC}"
echo -e "  CRYPTO_PASSWORD: $(echo $CRYPTO_PASSWORD | head -c 10)..."
echo -e "  CRYPTO_VAULT_PATH: ${CRYPTO_VAULT_PATH:-/mnt/crypto_vault}"
echo -e "  PAW_LOG_LEVEL: ${PAW_LOG_LEVEL:-INFO}"
echo -e "  Docker image: paw-analyzer"

echo -e "\n${YELLOW}Quick Start Commands:${NC}"
echo -e "  ${GREEN}# Analyze email (local)${NC}"
echo -e "  paw trace --src phishing.eml"
echo -e ""
echo -e "  ${GREEN}# Analyze email (Docker isolated)${NC}"
echo -e "  docker-compose run --rm paw-analyzer python -m paw trace --src /app/cases/phishing.eml"
echo -e ""
echo -e "  ${GREEN}# Detonate URL (Docker isolated)${NC}"
echo -e "  docker-compose run --rm paw-analyzer python -m paw detonate --url https://phishing-site.com --observe"
echo -e ""
echo -e "  ${GREEN}# Start canary server${NC}"
echo -e "  docker-compose up paw-analyzer"

echo -e "\n${YELLOW}Security Checklist:${NC}"
echo -e "  [ ] Review security_audit.json for code issues"
echo -e "  [ ] Review safety_audit.json for vulnerable dependencies"
echo -e "  [ ] Configure firewall rules for Docker network"
echo -e "  [ ] Set up log rotation for vault directory"
echo -e "  [ ] Configure backup for cases directory"
echo -e "  [ ] Test with known phishing samples in isolated environment"

echo -e "\n${YELLOW}Documentation:${NC}"
echo -e "  README.md          - Full documentation"
echo -e "  MIGRATION_GUIDE.md - Migration and remaining work"
echo -e "  .env.example       - Configuration template"

echo -e "\n${GREEN}Deployment successful!${NC}"
