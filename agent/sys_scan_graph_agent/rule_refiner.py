from __future__ import annotations
from typing import List, Dict
import os

# Placeholder real-model integration: in production, call external LLM API.
# Here we just append a deterministic note to rationale and ensure tags include 'llm_refined'.

def llm_refine(suggestions: List[Dict], examples: Dict[str,List[str]]) -> List[Dict]:
    for s in suggestions:
        rid = s.get('id','')
        ex = examples.get(rid, [])
        if ex:
            note = f"LLM refined using {len(ex)} examples"
        else:
            note = "LLM refined"
        rationale = s.get('rationale','')
        if note not in rationale:
            s['rationale'] = rationale + (" | " if rationale else "") + note
        tags = s.get('tags',[])
        if 'llm_refined' not in tags:
            tags.append('llm_refined')
        s['tags'] = tags
    return suggestions
