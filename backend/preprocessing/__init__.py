"""Source loading and Solidity preprocessing."""

from .feature_extractor import build_analysis_input, extract_static_features
from .source_loader import load_sources

__all__ = ["build_analysis_input", "extract_static_features", "load_sources"]
