"""
SB - Professional Security Scanner
Run manifest — writes run_config.json to the results directory for each scan
session. Records modules, timing, and active probe flags for reproducibility
and authorized engagement documentation.
"""
import json as _json
import os as _os
import threading
import time as _time

_lock = threading.Lock()


def _iso() -> str:
    return _time.strftime('%Y-%m-%dT%H:%M:%SZ', _time.gmtime())


def start_manifest(results_dir: str, config: dict) -> str:
    """
    Write initial run_config.json at scan start.
    Returns the manifest path for update_manifest().
    config should include: source, target_count, modules, active_probes,
    threads, timeout, skip_waf, resume, proxies.
    """
    record = {**config, 'start_time': _iso(), 'end_time': None,
              'findings_count': None, 'status': 'running'}
    path = _os.path.join(results_dir, 'run_config.json')
    _write(path, record)
    return path


def finish_manifest(path: str, findings_count: int, stopped: bool = False):
    """Update run_config.json with end time, findings count, and status."""
    try:
        with open(path, encoding='utf-8') as f:
            record = _json.load(f)
    except Exception:
        record = {}
    record.update(end_time=_iso(), findings_count=findings_count,
                  status='stopped' if stopped else 'completed')
    _write(path, record)


def _write(path: str, record: dict):
    tmp = path + '.tmp'
    try:
        with _lock:
            with open(tmp, 'w', encoding='utf-8') as f:
                _json.dump(record, f, indent=2, default=str)
            _os.replace(tmp, path)
    except Exception:
        pass
