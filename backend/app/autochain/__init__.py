"""
AutoChain — Automated Tool Chaining Engine
Provides the AutoChain orchestrator that fully automates the
recon → vulnerability discovery → exploitation → post-exploitation
pipeline without requiring a human to approve and invoke each step.

Public API
----------
from app.autochain import AutoChain, ScanPlan, ChainResult, ExploitCandidate
"""

from .schemas import ScanPlan, ChainResult, ExploitCandidate, ChainStep, ChainStatus
from .recon_mapper import ReconToExploitMapper
from .orchestrator import AutoChain

__all__ = [
    "AutoChain",
    "ScanPlan",
    "ChainResult",
    "ExploitCandidate",
    "ChainStep",
    "ChainStatus",
    "ReconToExploitMapper",
]
