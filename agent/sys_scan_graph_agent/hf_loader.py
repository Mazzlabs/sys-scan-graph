from __future__ import annotations
"""Utility helpers for optional Hugging Face dataset access without hardcoding tokens.

Usage:
    from agent.hf_loader import load_cybersec_jsonl, load_cybersec_parquet
    df1 = load_cybersec_jsonl()  # returns pandas.DataFrame or None
    df2 = load_cybersec_parquet()

The functions will:
  - Read HUGGINGFACE_TOKEN from environment (supports .env via python-dotenv if installed).
  - Fail gracefully if token or pandas is missing.
  - Avoid embedding secrets in code or logs.
"""
import os
from typing import Optional

def _get_token() -> Optional[str]:
    # Optional lazy load from python-dotenv if available.
    try:
        if '.env' in os.listdir('.'):
            try:
                from dotenv import load_dotenv  # type: ignore
                load_dotenv()
            except Exception:
                pass
    except Exception:
        pass
    tok = os.environ.get('HUGGINGFACE_TOKEN')
    if tok and tok.startswith('hf_'):
        return tok
    return None

def _import_pd():
    try:
        import pandas as pd  # type: ignore
        return pd
    except Exception:
        return None

_JSONL_PATH = "hf://datasets/Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset/CyberSec-Dataset_escaped.jsonl"
_PARQUET_PATH = "hf://datasets/Yemmy1000/cybersec_embedding_llama_chat/data/train-00000-of-00001-0f80939cab7cd7c6.parquet"

def load_cybersec_jsonl(lines: bool = True):
    pd = _import_pd()
    if not pd:
        return None
    tok = _get_token()
    if not tok:
        return None
    try:
        return pd.read_json(_JSONL_PATH, lines=lines)
    except Exception:
        return None

def load_cybersec_parquet():
    pd = _import_pd()
    if not pd:
        return None
    tok = _get_token()
    if not tok:
        return None
    try:
        return pd.read_parquet(_PARQUET_PATH)
    except Exception:
        return None
