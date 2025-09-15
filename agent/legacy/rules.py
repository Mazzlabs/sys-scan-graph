"""
Legacy rules module - imports functions from main rules directory for backward compatibility.
"""
try:
    import rules
    Correlator = rules.Correlator
    DEFAULT_RULES = rules.DEFAULT_RULES
    load_rules_dir = rules.load_rules_dir
except (ImportError, AttributeError):
    # Fallback for when rules module is not available
    Correlator = None
    DEFAULT_RULES = []
    load_rules_dir = lambda x: []