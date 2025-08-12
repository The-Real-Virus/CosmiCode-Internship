#!/usr/bin/env python3
"""
waf_log_analyzer.py

Simple log analysis automation for Apache access logs and ModSecurity audit logs.

Usage:
    python3 waf_log_analyzer.py --access /var/log/apache2/access.log \
                                --modsec /var/log/modsec_audit.log \
                                --outdir ./reports

    # quick test mode (uses synthetic sample logs embedded)
    python3 waf_log_analyzer.py --test --outdir ./reports_test

Outputs:
  - <outdir>/summary.json       : JSON summary of findings
  - <outdir>/top_ips.csv        : top IPs by requests and modsec hits
  - <outdir>/top_rules.csv      : top ModSecurity rule IDs
  - <outdir>/timeline.csv       : events per hour
  - console output summary
"""

from __future__ import annotations
import argparse
import csv
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Iterable

# ------------------
# Helper parsers
# ------------------

APACHE_CLF_REGEX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

# ModSecurity audit log entries: detect transaction boundaries and key lines.
MODSEC_BOUNDARY_RE = re.compile(r'^--(?P<txid>[0-9a-fA-F-]+)-([A-Z])--$')
MODSEC_REQLINE_RE = re.compile(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS) (?P<uri>\S+) HTTP/[\d\.]+')
MODSEC_RULE_RE = re.compile(r'Rule: (?P<id>\d+)\s*-\s*(?P<msg>.+)$')

def parse_apache_access(lines: Iterable[str]) -> List[Dict]:
    """Parse apache access log lines in Combined Log Format (CLF)."""
    out = []
    for ln in lines:
        m = APACHE_CLF_REGEX.search(ln)
        if not m:
            continue
        gd = m.groupdict()
        # parse time example: 12/Aug/2025:14:20:10 +0000
        try:
            dt = datetime.strptime(gd['time'].split()[0], '%d/%b/%Y:%H:%M:%S')
        except Exception:
            dt = None
        out.append({
            'ip': gd['ip'],
            'time': dt,
            'request': gd['request'],
            'status': int(gd['status']),
            'size': None if gd['size'] == '-' else int(gd['size']),
            'referrer': gd['referrer'],
            'agent': gd['agent'],
            'raw': ln.strip()
        })
    return out

def parse_modsec_audit(lines: Iterable[str]) -> List[Dict]:
    """
    Parse modsecurity audit log. This is conservative: we collect
    transactions by boundary lines and look for request line and Rule matches.
    """
    txs = []
    current = {'txid': None, 'raw': []}
    for ln in lines:
        ln = ln.rstrip('\n')
        m = MODSEC_BOUNDARY_RE.match(ln)
        if m:
            # boundary - if we have a current tx, finalize it
            if current['txid']:
                txs.append(current.copy())
            current = {'txid': m.group('txid'), 'raw': [], 'rules': [], 'request': None, 'ip': None}
            continue
        if current['txid'] is None:
            continue
        current['raw'].append(ln)
        # find request line
        r = MODSEC_REQLINE_RE.match(ln)
        if r and not current.get('request'):
            current['request'] = r.group(0)
        rr = MODSEC_RULE_RE.search(ln)
        if rr:
            current.setdefault('rules', []).append({'id': int(rr.group('id')), 'msg': rr.group('msg').strip()})
        # optional: capture client IP line format e.g. [12/Aug/2025:14:11:01 +0000] 192.168.1.10 ...
        # quick IP detection
        if not current.get('ip'):
            ip_search = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', ln)
            if ip_search:
                current['ip'] = ip_search.group(1)
    # append last transaction
    if current.get('txid'):
        txs.append(current)
    return txs

# ------------------
# Analysis functions
# ------------------

def analyze_access(records: List[Dict]) -> Dict:
    ip_counter = Counter()
    status_counter = Counter()
    hourly = Counter()
    sample_requests = []
    for r in records:
        ip_counter[r['ip']] += 1
        status_counter[str(r['status'])] += 1
        if r['time']:
            hour = r['time'].strftime('%Y-%m-%d %H:00:00')
            hourly[hour] += 1
        sample_requests.append((r['ip'], r['request'], r['status'], r['agent']))
    top_ips = ip_counter.most_common(50)
    return {
        'top_ips': top_ips,
        'status_counts': status_counter.most_common(),
        'hourly': sorted(hourly.items()),
        'samples': sample_requests[:20]
    }

def analyze_modsec(txs: List[Dict]) -> Dict:
    ip_counter = Counter()
    rule_counter = Counter()
    hourly = Counter()
    samples = []
    for t in txs:
        ip = t.get('ip') or 'unknown'
        ip_counter[ip] += 1
        for rule in t.get('rules', []):
            rule_counter[rule['id']] += 1
        # try to extract a timestamp from raw lines (simple heuristic)
        for ln in t['raw']:
            if ln.startswith('[') and ']' in ln:
                try:
                    ts_part = ln.split(']')[0].lstrip('[')
                    dt = datetime.strptime(ts_part.split()[0], '%d/%b/%Y:%H:%M:%S')
                    hour = dt.strftime('%Y-%m-%d %H:00:00')
                    hourly[hour] += 1
                    break
                except Exception:
                    continue
        samples.append({'txid': t.get('txid'), 'ip': ip, 'request': t.get('request'), 'rules': t.get('rules')})
    return {
        'top_ips': ip_counter.most_common(50),
        'top_rules': rule_counter.most_common(100),
        'hourly': sorted(hourly.items()),
        'samples': samples[:30]
    }

# ------------------
# Reporting / exports
# ------------------

def export_csv(path: str, rows: Iterable[Tuple], headers: List[str]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='', encoding='utf-8') as fh:
        writer = csv.writer(fh)
        writer.writerow(headers)
        for r in rows:
            writer.writerow(r)

def save_json(path: str, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as fh:
        json.dump(obj, fh, indent=2, default=str)

# ------------------
# CLI and main
# ------------------

SAMPLE_APACHE = [
    '192.168.0.104 - - [12/Aug/2025:06:17:01 +0000] "GET /login HTTP/1.1" 200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '192.168.0.105 - - [12/Aug/2025:06:18:12 +0000] "GET / HTTP/1.1" 200 512 "-" "curl/7.68.0"',
    '192.168.0.104 - - [12/Aug/2025:06:18:15 +0000] "POST /login HTTP/1.1" 302 0 "-" "Mozilla/5.0 (Windows)"',
]

SAMPLE_MODSEC = [
    "--0a1b2c3d-A--",
    "[12/Aug/2025:06:18:15 +0000] 192.168.0.104 192.168.0.107 12345 80",
    "--0a1b2c3d-B--",
    "POST /login.php HTTP/1.1",
    "Host: localhost",
    "--0a1b2c3d-F--",
    "Matched Data: admin found within ARGS:password",
    "Action: Intercepted (phase 2)",
    "Rule: 941100 - XSS Attack Detected",
    "--0a1b2c3d-Z--"
]

def main():
    p = argparse.ArgumentParser(description='WAF & Apache log analyzer')
    p.add_argument('--access', help='Path to Apache access log (CLF/combined)')
    p.add_argument('--modsec', help='Path to ModSecurity audit log')
    p.add_argument('--outdir', required=True, help='Output directory for reports')
    p.add_argument('--test', action='store_true', help='Run with embedded sample logs (for testing)')
    args = p.parse_args()

    if args.test:
        access_lines = SAMPLE_APACHE
        modsec_lines = SAMPLE_MODSEC
    else:
        if not args.access or not args.modsec:
            p.error('Either use --test or provide both --access and --modsec')
        with open(args.access, 'r', encoding='utf-8', errors='ignore') as f:
            access_lines = f.readlines()
        with open(args.modsec, 'r', encoding='utf-8', errors='ignore') as f:
            modsec_lines = f.readlines()

    access_records = parse_apache_access(access_lines)
    modsec_txs = parse_modsec_audit(modsec_lines)

    access_summary = analyze_access(access_records)
    modsec_summary = analyze_modsec(modsec_txs)

    # Combine into one summary
    summary = {
        'meta': {
            'generated': datetime.utcnow().isoformat() + 'Z',
            'access_records': len(access_records),
            'modsec_transactions': len(modsec_txs)
        },
        'access': access_summary,
        'modsecurity': modsec_summary
    }

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)

    # Exports
    save_json(os.path.join(outdir, 'summary.json'), summary)
    export_csv(os.path.join(outdir, 'top_ips.csv'),
               [(ip, cnt) for ip, cnt in access_summary['top_ips']],
               ['ip', 'access_count'])
    export_csv(os.path.join(outdir, 'top_rules.csv'),
               [(rid, cnt) for rid, cnt in modsec_summary['top_rules']],
               ['rule_id', 'count'])
    export_csv(os.path.join(outdir, 'timeline.csv'),
               access_summary['hourly'],
               ['hour', 'access_count'])

    # Print a short summary to stdout
    print('WAF Log Analyzer — Summary')
    print('-------------------------')
    print(f"Access records parsed: {len(access_records)}")
    print(f"ModSecurity transactions parsed: {len(modsec_txs)}")
    print()
    print('Top Access IPs:')
    for ip, cnt in access_summary['top_ips'][:10]:
        print(f"  {ip:15} {cnt:5d}")
    print()
    print('Top ModSecurity Rule IDs:')
    for rid, cnt in modsec_summary['top_rules'][:10]:
        print(f"  {rid:8d} {cnt:5d}")
    print()
    print(f"Reports written to: {os.path.abspath(outdir)}")

if __name__ == '__main__':
    main()
