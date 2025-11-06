# paw/sentinel/__init__.py
"""
Sentinel - Continuous Phishing Campaign Monitoring Module

This module provides continuous monitoring capabilities for active phishing campaigns,
enabling proactive detection of changes, automated alerts, and campaign lifecycle tracking.
"""

__version__ = "1.0.0"
__author__ = "PAW Team"

from .config import SentinelConfig
from .monitor import SentinelMonitor
from .database import CampaignDatabase
from .file_monitor import FileMonitor
from .ip_analyzer import IPAnalyzer
from .intelligence_analyzer import IntelligenceAnalyzer

__all__ = ['SentinelConfig', 'SentinelMonitor', 'CampaignDatabase', 'FileMonitor', 'IPAnalyzer', 'IntelligenceAnalyzer']