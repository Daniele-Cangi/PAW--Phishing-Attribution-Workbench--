"""
PAW Input Validation Framework
Centralized validation for all user inputs
"""

import re
import os
import ipaddress
from typing import Optional
from urllib.parse import urlparse


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


class InputValidator:
    """Centralized input validation for PAW"""

    @staticmethod
    def validate_url(url: str, allow_http: bool = True) -> str:
        """Validate and sanitize URL

        Args:
            url: URL to validate
            allow_http: Allow HTTP scheme (default True for phishing analysis)

        Returns:
            Validated URL string

        Raises:
            ValidationError: If URL is invalid
        """
        if not isinstance(url, str):
            raise ValidationError("URL must be string")

        url = url.strip()

        if not url:
            raise ValidationError("URL cannot be empty")

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise ValidationError(f"Invalid URL format: {e}")

        # Validate scheme
        if not parsed.scheme:
            raise ValidationError("URL must include scheme (http:// or https://)")

        if parsed.scheme not in ['http', 'https']:
            raise ValidationError(f"Invalid URL scheme: {parsed.scheme}")

        if not allow_http and parsed.scheme == 'http':
            raise ValidationError("HTTP not allowed, use HTTPS")

        # Validate hostname
        if not parsed.netloc:
            raise ValidationError("URL must include hostname")

        # Basic hostname validation
        hostname = parsed.netloc.split(':')[0]  # Remove port
        if not InputValidator._is_valid_hostname(hostname):
            raise ValidationError(f"Invalid hostname: {hostname}")

        return url

    @staticmethod
    def validate_ip(ip: str) -> str:
        """Validate IP address (v4 or v6)

        Args:
            ip: IP address string

        Returns:
            Validated IP string

        Raises:
            ValidationError: If IP is invalid
        """
        if not isinstance(ip, str):
            raise ValidationError("IP must be string")

        ip = ip.strip()

        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Invalid IP address: {ip}")

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate domain name

        Args:
            domain: Domain name string

        Returns:
            Validated domain string (lowercase)

        Raises:
            ValidationError: If domain is invalid
        """
        if not isinstance(domain, str):
            raise ValidationError("Domain must be string")

        domain = domain.strip().lower()

        if not domain:
            raise ValidationError("Domain cannot be empty")

        # Remove scheme if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]

        # Remove path if present
        domain = domain.split('/')[0]

        # Remove port if present
        domain = domain.split(':')[0]

        # Basic domain regex
        pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
        if not re.match(pattern, domain):
            raise ValidationError(f"Invalid domain format: {domain}")

        # Additional checks
        if len(domain) > 253:
            raise ValidationError("Domain too long (max 253 characters)")

        labels = domain.split('.')
        for label in labels:
            if len(label) > 63:
                raise ValidationError(f"Domain label too long: {label} (max 63 characters)")

        return domain

    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email address

        Args:
            email: Email address string

        Returns:
            Validated email string (lowercase)

        Raises:
            ValidationError: If email is invalid
        """
        if not isinstance(email, str):
            raise ValidationError("Email must be string")

        email = email.strip().lower()

        if not email:
            raise ValidationError("Email cannot be empty")

        # Basic email regex
        pattern = r'^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$'
        if not re.match(pattern, email):
            raise ValidationError(f"Invalid email format: {email}")

        # Validate domain part
        domain = email.split('@')[1]
        try:
            InputValidator.validate_domain(domain)
        except ValidationError as e:
            raise ValidationError(f"Invalid email domain: {e}")

        return email

    @staticmethod
    def sanitize_filename(filename: str, allow_path: bool = False) -> str:
        """Sanitize filename to prevent path traversal

        Args:
            filename: Filename to sanitize
            allow_path: Allow path separators (default False)

        Returns:
            Sanitized filename string

        Raises:
            ValidationError: If filename is invalid
        """
        if not isinstance(filename, str):
            raise ValidationError("Filename must be string")

        filename = filename.strip()

        if not filename:
            raise ValidationError("Filename cannot be empty")

        # Remove path if not allowed
        if not allow_path:
            filename = os.path.basename(filename)

        # Check for path traversal attempts
        if '..' in filename:
            raise ValidationError("Path traversal detected in filename")

        if not allow_path and ('/' in filename or '\\' in filename):
            raise ValidationError("Path separators not allowed in filename")

        # Remove dangerous characters
        filename = re.sub(r'[^\w\s.-]', '_', filename)

        # Prevent hidden files
        if filename.startswith('.') and len(filename) > 1:
            filename = '_' + filename[1:]

        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext

        return filename

    @staticmethod
    def validate_path(path: str, base_path: Optional[str] = None) -> str:
        """Validate file path and prevent traversal attacks

        Args:
            path: Path to validate
            base_path: Base directory to restrict to (optional)

        Returns:
            Validated absolute path

        Raises:
            ValidationError: If path is invalid or outside base_path
        """
        if not isinstance(path, str):
            raise ValidationError("Path must be string")

        path = path.strip()

        if not path:
            raise ValidationError("Path cannot be empty")

        # Convert to absolute path
        abs_path = os.path.abspath(path)

        # Check if within base_path
        if base_path:
            base_abs = os.path.abspath(base_path)
            if not abs_path.startswith(base_abs):
                raise ValidationError(f"Path outside allowed directory: {abs_path}")

        return abs_path

    @staticmethod
    def validate_port(port: int) -> int:
        """Validate network port number

        Args:
            port: Port number

        Returns:
            Validated port number

        Raises:
            ValidationError: If port is invalid
        """
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                raise ValidationError(f"Port must be integer, got: {type(port)}")

        if port < 1 or port > 65535:
            raise ValidationError(f"Port must be 1-65535, got: {port}")

        return port

    @staticmethod
    def validate_asn(asn: int) -> int:
        """Validate ASN (Autonomous System Number)

        Args:
            asn: ASN number

        Returns:
            Validated ASN

        Raises:
            ValidationError: If ASN is invalid
        """
        if not isinstance(asn, int):
            try:
                asn = int(asn)
            except (ValueError, TypeError):
                raise ValidationError(f"ASN must be integer, got: {type(asn)}")

        if asn < 0 or asn > 4294967295:  # Max 32-bit ASN
            raise ValidationError(f"Invalid ASN: {asn}")

        return asn

    @staticmethod
    def _is_valid_hostname(hostname: str) -> bool:
        """Check if hostname is valid format"""
        if not hostname or len(hostname) > 253:
            return False

        # Allow IP addresses
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass

        # Check hostname format
        if hostname[-1] == ".":
            hostname = hostname[:-1]

        allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(label) for label in hostname.split("."))


# Convenience functions
def validate_url(url: str, allow_http: bool = True) -> str:
    """Shorthand for InputValidator.validate_url()"""
    return InputValidator.validate_url(url, allow_http)


def validate_domain(domain: str) -> str:
    """Shorthand for InputValidator.validate_domain()"""
    return InputValidator.validate_domain(domain)


def validate_ip(ip: str) -> str:
    """Shorthand for InputValidator.validate_ip()"""
    return InputValidator.validate_ip(ip)


def validate_email(email: str) -> str:
    """Shorthand for InputValidator.validate_email()"""
    return InputValidator.validate_email(email)


def sanitize_filename(filename: str) -> str:
    """Shorthand for InputValidator.sanitize_filename()"""
    return InputValidator.sanitize_filename(filename)
