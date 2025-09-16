from __future__ import annotations
import sqlite3, time, datetime
from pathlib import Path
from typing import Iterable, Tuple, Dict, List, Optional
import models

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS baseline_finding (
    host_id TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    first_seen_ts INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    seen_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(host_id, finding_hash)
);
CREATE TABLE IF NOT EXISTS baseline_meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS baseline_scan (
    host_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    PRIMARY KEY(host_id, scan_id)
);
"""

# Added in schema version 2
SCHEMA_V2 = """
CREATE TABLE IF NOT EXISTS calibration_observation (
    host_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    finding_hash TEXT NOT NULL,
    raw_weighted_sum REAL NOT NULL,
    analyst_decision TEXT NULL, -- tp|fp|ignore
    ts INTEGER NOT NULL,
    PRIMARY KEY(host_id, scan_id, finding_hash)
);
"""

# Added in schema version 3 (module rarity aggregation)
SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS module_observation (
    host_id TEXT NOT NULL,
    module TEXT NOT NULL,
    first_seen_ts INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    seen_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY(host_id, module)
);
"""

# Added in schema version 4 (metric drift tracking)
SCHEMA_V4 = """
CREATE TABLE IF NOT EXISTS baseline_metric (
    host_id TEXT NOT NULL,
    metric TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    value REAL NOT NULL,
    PRIMARY KEY(host_id, metric, scan_id)
);
"""
SCHEMA_V5 = """
CREATE TABLE IF NOT EXISTS process_cluster (
    host_id TEXT NOT NULL,
    cluster_id INTEGER NOT NULL,
    count INTEGER NOT NULL DEFAULT 0,
    sum_vector TEXT NOT NULL, -- JSON encoded list[float]
    first_seen_ts INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    last_update_ts INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    PRIMARY KEY(host_id, cluster_id)
);
"""
CURRENT_SCHEMA_VERSION = 5

class BaselineStore:
    def __init__(self, path: Path):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self._migrate()

    def _migrate(self):
        cur = self.conn.cursor()
        cur.executescript(SCHEMA_V1)
        # Check version
        row = cur.execute("SELECT value FROM baseline_meta WHERE key='schema_version'").fetchone()
        if not row:
            # Fresh DB: apply all subsequent schema segments
            cur.executescript(SCHEMA_V2)
            cur.executescript(SCHEMA_V3)
            cur.executescript(SCHEMA_V4)
            cur.executescript(SCHEMA_V5)
            cur.execute("INSERT OR REPLACE INTO baseline_meta(key,value) VALUES('schema_version',?)", (str(CURRENT_SCHEMA_VERSION),))
        else:
            ver = int(row[0])
            if ver > CURRENT_SCHEMA_VERSION:
                raise RuntimeError(f"Baseline DB schema version {ver} newer than supported {CURRENT_SCHEMA_VERSION}")
            if ver < 2:
                # apply v2 additions
                cur.executescript(SCHEMA_V2)
                ver = 2
            if ver < 3:
                cur.executescript(SCHEMA_V3)
                ver = 3
            if ver < 4:
                cur.executescript(SCHEMA_V4)
                ver = 4
            if ver < 5:
                cur.executescript(SCHEMA_V5)
                ver = 5
            if ver != CURRENT_SCHEMA_VERSION:
                cur.execute("UPDATE baseline_meta SET value=? WHERE key='schema_version'", (str(CURRENT_SCHEMA_VERSION),))
        self.conn.commit()

    def update_and_diff(self, host_id: str, findings: Iterable[Tuple[str, models.Finding]]):
        """Return dict mapping finding id(hash) -> delta info.
        Input iterable yields (scanner, finding)
        """
        cur = self.conn.cursor()
        deltas = {}
        for scanner, f in findings:
            # Composite hash includes scanner to avoid collisions across scanners reusing ids
            h = f.identity_hash()
            composite = hashlib_sha(scanner, h)
            row = cur.execute("SELECT first_seen_ts, seen_count FROM baseline_finding WHERE host_id=? AND finding_hash=?", (host_id, composite)).fetchone()
            if row:
                first_seen, count = row
                cur.execute("UPDATE baseline_finding SET seen_count=seen_count+1 WHERE host_id=? AND finding_hash=?", (host_id, composite))
                deltas[composite] = {"status": "existing", "first_seen_ts": first_seen, "prev_seen_count": count}
            else:
                cur.execute("INSERT INTO baseline_finding(host_id,finding_hash) VALUES(?,?)", (host_id, composite))
                deltas[composite] = {"status": "new"}
            # Track module occurrence for rarity if module scanner
            if scanner.lower() in {"modules","kernel_modules"}:
                mod = f.metadata.get("module") if f.metadata else None
                if mod:
                    mrow = cur.execute("SELECT first_seen_ts, seen_count FROM module_observation WHERE host_id=? AND module=?", (host_id, mod)).fetchone()
                    if mrow:
                        cur.execute("UPDATE module_observation SET seen_count=seen_count+1 WHERE host_id=? AND module=?", (host_id, mod))
                    else:
                        cur.execute("INSERT INTO module_observation(host_id,module) VALUES(?,?)", (host_id, mod))
        self.conn.commit()
        return deltas

    # Calibration logging utilities
    def log_calibration_observation(self, host_id: str, scan_id: str, finding_hash: str, raw_weighted_sum: float):
        cur = self.conn.cursor()
        ts = int(time.time())
        try:
            cur.execute("INSERT OR IGNORE INTO calibration_observation(host_id,scan_id,finding_hash,raw_weighted_sum,ts) VALUES(?,?,?,?,?)",
                        (host_id, scan_id, finding_hash, raw_weighted_sum, ts))
            # Removed individual commit for batching
        except Exception:
            pass

    def update_calibration_decision(self, host_id: str, finding_hash: str, decision: str):
        if decision not in {"tp","fp","ignore"}:
            raise ValueError("decision must be tp|fp|ignore")
        cur = self.conn.cursor()
        cur.execute("UPDATE calibration_observation SET analyst_decision=? WHERE host_id=? AND finding_hash=?",
                    (decision, host_id, finding_hash))
        self.conn.commit()

    def fetch_pending_calibration(self, host_id: str, limit: int = 50):
        cur = self.conn.cursor()
        rows = cur.execute("SELECT finding_hash, raw_weighted_sum, ts FROM calibration_observation WHERE host_id=? AND analyst_decision IS NULL ORDER BY ts DESC LIMIT ?",
                           (host_id, limit)).fetchall()
        return [{"finding_hash": fh, "raw_weighted_sum": rw, "ts": ts} for (fh, rw, ts) in rows]

    def record_scan(self, host_id: str, scan_id: str, ts: Optional[int] = None):
        if ts is None:
            ts = int(time.time())
        cur = self.conn.cursor()
        try:
            cur.execute("INSERT OR IGNORE INTO baseline_scan(host_id,scan_id,ts) VALUES(?,?,?)", (host_id, scan_id, ts))
            self.conn.commit()
        except Exception:
            pass

    def scan_days_present(self, host_id: str, days: int) -> Dict[str,bool]:
        cutoff = int(time.time()) - days*86400
        cur = self.conn.cursor()
        rows = cur.execute("SELECT ts FROM baseline_scan WHERE host_id=? AND ts>=?", (host_id, cutoff)).fetchall()
        day_set = set()
        for (ts,) in rows:
            day = datetime.date.fromtimestamp(ts).isoformat()
            day_set.add(day)
        present = {}
        for d in range(days, -1, -1):
            day_date = datetime.date.fromtimestamp(int(time.time()) - d*86400).isoformat()
            present[day_date] = day_date in day_set
        return present

    def diff_since_days(self, host_id: str, days: int) -> List[Dict[str, int]]:
        cutoff = int(time.time()) - days*86400
        cur = self.conn.cursor()
        rows = cur.execute("SELECT finding_hash, first_seen_ts FROM baseline_finding WHERE host_id=? AND first_seen_ts>=?", (host_id, cutoff)).fetchall()
        return [{"finding_hash": fh, "first_seen_ts": ts} for (fh, ts) in rows]

    # Module rarity aggregation
    def aggregate_module_frequencies(self) -> Dict[str, int]:
        """Return mapping module -> distinct host count (presence frequency)."""
        cur = self.conn.cursor()
        rows = cur.execute("SELECT module, COUNT(DISTINCT host_id) AS host_count FROM module_observation GROUP BY module").fetchall()
        return {module: host_count for (module, host_count) in rows}

    def recent_module_first_seen(self, within_seconds: int = 86400) -> Dict[str, list]:
        """Return mapping module -> list of host_ids where module first_seen within window (simultaneous emergence)."""
        cutoff = int(time.time()) - within_seconds
        cur = self.conn.cursor()
        rows = cur.execute("SELECT module, host_id FROM module_observation WHERE first_seen_ts >= ?", (cutoff,)).fetchall()
        agg: Dict[str, list] = {}
        for module, host_id in rows:
            agg.setdefault(module, []).append(host_id)
        return agg

    # ---- Fleet-level metrics helpers ----
    def latest_metric_values(self, metric: str) -> List[Tuple[str, float, int]]:
        """Return list of (host_id, value, ts) for latest value of metric per host."""
        cur = self.conn.cursor()
        rows = cur.execute(
            """
            SELECT bm.host_id, bm.value, bm.ts FROM baseline_metric bm
            JOIN (
              SELECT host_id, MAX(ts) AS mts FROM baseline_metric WHERE metric=? GROUP BY host_id
            ) t ON bm.host_id=t.host_id AND bm.ts=t.mts AND bm.metric=?
            """, (metric, metric)).fetchall()
        return [(host_id, value, ts) for (host_id, value, ts) in rows]

    def metric_history(self, host_id: str, metric: str, limit: int = 50) -> List[Tuple[float,int]]:
        cur = self.conn.cursor()
        rows = cur.execute("SELECT value, ts FROM baseline_metric WHERE host_id=? AND metric=? ORDER BY ts DESC LIMIT ?", (host_id, metric, limit)).fetchall()
        return [(value, ts) for (value, ts) in rows]

    # ---- Metric drift tracking ----
    def _get_meta(self, key: str) -> Optional[str]:
        cur = self.conn.cursor()
        row = cur.execute("SELECT value FROM baseline_meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def _set_meta(self, key: str, value: str):
        cur = self.conn.cursor()
        cur.execute("INSERT OR REPLACE INTO baseline_meta(key,value) VALUES(?,?)", (key, value))
        self.conn.commit()

    def record_metrics(self, host_id: str, scan_id: str, metrics: Dict[str, float], ts: Optional[int] = None, history_limit: int = 30, ewma_alpha: float = 0.3):
        """Record per-scan metrics and compute z-scores & EWMA.
        Returns dict metric->{value, mean, std, z, ewma_prev, ewma_new, history_n} (excluding current)"""
        if ts is None:
            ts = int(time.time())
        cur = self.conn.cursor()
        results = {}
        for name, value in metrics.items():
            # Insert current value
            try:
                cur.execute("INSERT OR REPLACE INTO baseline_metric(host_id,metric,scan_id,ts,value) VALUES(?,?,?,?,?)",
                            (host_id, name, scan_id, ts, float(value)))
            except Exception:
                pass
            # Fetch history excluding this scan id
            rows = cur.execute(
                "SELECT value FROM baseline_metric WHERE host_id=? AND metric=? AND scan_id!=? ORDER BY ts DESC LIMIT ?",
                (host_id, name, scan_id, history_limit)
            ).fetchall()
            history = [r[0] for r in rows]
            mean = std = z = None
            # Compute mean/std with as few as 2 historical points (early drift sensitivity)
            if len(history) >= 2:
                mean = sum(history)/len(history)
                # sample std
                var = sum((x-mean)**2 for x in history)/(len(history)-1) if len(history) > 1 else 0.0
                std = var**0.5
                if std and std > 0:
                    z = (value - mean)/std
            # EWMA
            ewma_key = f"ewma:{host_id}:{name}"
            ewma_prev = self._get_meta(ewma_key)
            try:
                ewma_prev_val = float(ewma_prev) if ewma_prev is not None else None
            except ValueError:
                ewma_prev_val = None
            if ewma_prev_val is None:
                ewma_new = value
            else:
                ewma_new = ewma_alpha * value + (1-ewma_alpha) * ewma_prev_val
            self._set_meta(ewma_key, str(ewma_new))
            results[name] = {
                'value': value,
                'mean': mean,
                'std': std,
                'z': z,
                'ewma_prev': ewma_prev_val,
                'ewma_new': ewma_new,
                'history_n': len(history)
            }
        self.conn.commit()
        return results

    # ---- Process similarity / embedding clusters (schema v5) ----
    def _process_clusters(self, host_id: str):
        cur = self.conn.cursor()
        rows = cur.execute("SELECT cluster_id, count, sum_vector FROM process_cluster WHERE host_id=?", (host_id,)).fetchall()
        import json
        out = []
        for cid, count, sv in rows:
            try:
                vec = json.loads(sv)
            except Exception:
                vec = []
            out.append((cid, count, vec))
        return out

    def _upsert_process_cluster(self, host_id: str, cluster_id: int, vector: list[float]):
        import json, time as _t
        cur = self.conn.cursor()
        # Fetch existing
        row = cur.execute("SELECT count, sum_vector FROM process_cluster WHERE host_id=? AND cluster_id=?", (host_id, cluster_id)).fetchone()
        if row:
            count, sv = row
            try:
                cur_vec = json.loads(sv)
            except Exception:
                cur_vec = [0.0]*len(vector)
            # Element-wise add
            new_sum = [a+b for a,b in zip(cur_vec, vector)]
            cur.execute("UPDATE process_cluster SET count=?, sum_vector=?, last_update_ts=strftime('%s','now') WHERE host_id=? AND cluster_id=?",
                        (count+1, json.dumps(new_sum), host_id, cluster_id))
        else:
            cur.execute("INSERT INTO process_cluster(host_id, cluster_id, count, sum_vector) VALUES(?,?,?,?)",
                        (host_id, cluster_id, 1, json.dumps(vector)))
        self.conn.commit()

    def _allocate_process_cluster(self, host_id: str) -> int:
        cur = self.conn.cursor()
        row = cur.execute("SELECT MAX(cluster_id) FROM process_cluster WHERE host_id=?", (host_id,)).fetchone()
        max_id = row[0] if row and row[0] is not None else -1
        return max_id + 1

    def assign_process_vector(self, host_id: str, vector: list[float], distance_threshold: float = 0.35):
        """Assign process feature vector to existing cluster or create new if far. Returns (cluster_id, distance, is_new)."""
        import math
        clusters = self._process_clusters(host_id)
        # Compute norms
        def norm(v):
            return math.sqrt(sum(x*x for x in v)) or 1.0
        v_norm = norm(vector)
        best = None
        for cid, count, sum_vec in clusters:
            if not sum_vec:
                continue
            centroid = [x / max(count,1) for x in sum_vec]
            c_norm = norm(centroid)
            dot = sum(a*b for a,b in zip(vector, centroid))
            cosine_sim = dot / (v_norm * c_norm)
            distance = 1 - cosine_sim
            if best is None or distance < best[1]:
                best = (cid, distance)
        if best is None or best[1] > distance_threshold:
            cid = self._allocate_process_cluster(host_id)
            self._upsert_process_cluster(host_id, cid, vector)
            return cid, best[1] if best else 1.0, True
        else:
            self._upsert_process_cluster(host_id, best[0], vector)
            return best[0], best[1], False

# ---- Embedding utilities (stateless) ----
import hashlib as _hashlib, re as _re
_TOKEN_RE = _re.compile(r"[A-Za-z0-9_]+")

def process_feature_vector(proc: str, dim: int = 32) -> list[float]:
    """Deterministic lightweight embedding for a process / cmd string.
    Strategy: tokenize alphanum, hash tokens to buckets, count, then L2 normalize.
    Adds two global features (digit_ratio, token_count/10) into last two dims.
    """
    if not proc:
        return [0.0]*dim
    tokens = _TOKEN_RE.findall(proc.lower())
    vec = [0.0]*dim
    if not tokens:
        return vec
    digit_chars = sum(c.isdigit() for c in proc)
    for t in tokens:
        h = int.from_bytes(_hashlib.sha256(t.encode()).digest()[:4], 'big')
        idx = h % (dim-2)  # reserve last 2 dims
        vec[idx] += 1.0
    # Global features
    total_chars = len(proc)
    vec[-2] = round(digit_chars / max(1,total_chars), 4)
    vec[-1] = min(len(tokens)/10.0, 1.0)
    # Normalize counts portion
    import math
    norm = math.sqrt(sum(x*x for x in vec)) or 1.0
    vec = [x / norm for x in vec]
    return vec


def hashlib_sha(scanner: str, h: str) -> str:
    import hashlib
    dig = hashlib.sha256()
    dig.update(scanner.encode())
    dig.update(b":")
    dig.update(h.encode())
    return dig.hexdigest()

