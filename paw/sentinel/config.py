# paw/sentinel/config.py
"""
Configuration management for Sentinel monitoring module.
"""
import os
import json
from typing import Dict, Any, Optional
from ..util.fsutil import ensure_dir, read_json, write_json


class SentinelConfig:
    """Configuration manager for Sentinel monitoring."""

    def __init__(self, config_file: str = None):
        self.config_file = config_file or os.path.join(os.getcwd(), "sentinel_config.json")
        self._config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create defaults."""
        if os.path.exists(self.config_file):
            return read_json(self.config_file) or self._get_defaults()
        return self._get_defaults()

    def _get_defaults(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "monitoring": {
                "enabled": True,
                "check_interval_minutes": 30,  # Check campaigns every 30 minutes
                "max_concurrent_checks": 5,    # Max parallel checks
                "timeout_seconds": 30,         # Timeout for each check
                "max_retries": 3,             # Retry failed checks
            },
            "alerts": {
                "enabled": True,
                "webhook_url": None,          # Optional webhook for alerts
                "email_alerts": False,        # Email notifications
                "alert_on_changes": True,     # Alert when content changes
                "alert_on_down": True,        # Alert when site goes down
                "alert_on_up": False,         # Alert when site comes back up
            },
            "storage": {
                "database_path": "sentinel.db",
                "screenshots_dir": "screenshots",
                "max_screenshots_per_campaign": 50,
                "retention_days": 90,         # Keep data for 90 days
            },
            "analysis": {
                "enable_screenshots": True,
                "enable_content_diff": True,
                "enable_fingerprinting": True,
                "screenshot_resolution": "1280x720",
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by dot-notation key."""
        keys = key.split('.')
        value = self._config
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default

    def set(self, key: str, value: Any) -> None:
        """Set configuration value by dot-notation key."""
        keys = key.split('.')
        config = self._config
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        config[keys[-1]] = value
        self._save_config()

    def _save_config(self) -> None:
        """Save configuration to file."""
        ensure_dir(os.path.dirname(self.config_file))
        write_json(self.config_file, self._config)

    def reset_to_defaults(self) -> None:
        """Reset configuration to default values."""
        self._config = self._get_defaults()
        self._save_config()

    def get_monitoring_config(self) -> Dict[str, Any]:
        """Get monitoring-specific configuration."""
        return self._config.get("monitoring", {})

    def get_alert_config(self) -> Dict[str, Any]:
        """Get alert-specific configuration."""
        return self._config.get("alerts", {})

    def get_storage_config(self) -> Dict[str, Any]:
        """Get storage-specific configuration."""
        return self._config.get("storage", {})

    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis-specific configuration."""
        return self._config.get("analysis", {})