"""
Resource Enumeration Module

Comprehensive endpoint discovery using Katana, GAU, and Kiterunner.
Implements parallel execution, URL merging, deduplication, and classification.

Author: BitR1FT (BitR1FT)
Developed by: BitR1FT
"""

from .schemas import (
    ResourceEnumRequest,
    EndpointInfo,
    ParameterInfo,
    FormInfo,
    ResourceEnumResult,
    ResourceEnumStats,
    EnumMode,
    EndpointCategory,
    ParameterType,
)
from .katana_wrapper import KatanaWrapper
from .gau_wrapper import GAUWrapper
from .kiterunner_wrapper import KiterunnerWrapper
from .resource_orchestrator import ResourceOrchestrator
from .katana_orchestrator import KatanaOrchestrator, KatanaConfig
from .gau_orchestrator import GAUOrchestrator, GAUConfig
from .kiterunner_orchestrator import KiterunnerOrchestrator, KiterunnerConfig
from .url_merger import URLMerger, URLCategory, normalise_url, categorise_url

__all__ = [
    "ResourceEnumRequest",
    "EndpointInfo",
    "ParameterInfo",
    "FormInfo",
    "ResourceEnumResult",
    "ResourceEnumStats",
    "EnumMode",
    "EndpointCategory",
    "ParameterType",
    "KatanaWrapper",
    "GAUWrapper",
    "KiterunnerWrapper",
    "ResourceOrchestrator",
    "KatanaOrchestrator",
    "KatanaConfig",
    "GAUOrchestrator",
    "GAUConfig",
    "KiterunnerOrchestrator",
    "KiterunnerConfig",
    "URLMerger",
    "URLCategory",
    "normalise_url",
    "categorise_url",
]

__version__ = "1.0.0"
__author__ = "BitR1FT"
