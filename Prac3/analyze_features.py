"""
Parse 'features/' directory and produce summary CSV + PNG plots based on:
 - imports (*.imports.txt)
 - strings (*.strings.txt)
 - urls (*.urls.txt)
 - meta (*.meta.txt)

Usage:
    python3 analyze_features.py --features-dir /path/to/features --outdir out
"""

import argparse
import os
import re
from pathlib import Path
from collections import Counter, defaultdict
import json
import math
import datetime

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# regular expressions to help
RE_SHA256 = re.compile(r'\b([a-fA-F0-9]{64})\b')
RE_SIZE = re.compile(r'Size:\s*([0-9]+)')
RE_SECTIONS = re.compile(r'(\d+)\s+sections')
RE_COMPILE_TS = re.compile(r'Compile timestamp:\s*(\d{9,10})')
RE_PE_TYPE = re.compile(r'PE32\+|PE32')  # capture PE32+ (64-bit) vs PE32
RE_URL = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
SUSPICIOUS_KEYWORDS = [
    'powershell', 'Invoke-Expression', '-nop', '-w hidden', '-windowstyle', 'wget', 'curl',
    'cmd.exe', 'regsvr32', 'schtasks', 'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
    'base64', 'eval(', 'download', '.onion'
]

def parse_imports_file(path):
    """
    Parse imports file. Expected format:
      SHLWAPI.dll
         b'PathRemoveExtensionW'
      KERNEL32.dll
         b'HeapReAlloc'
    Returns: dict with keys:
      - dlls: Counter of dll names (1 per dll occurrence)
      - functions: Counter of function names (aggregated across dlls)
      - num_imports: number of imported functions
    """
    dll_counter = Counter()
    func_counter = Counter()
    num_funcs = 0
    current_dll = None

    try:
        with open(path, 'rb') as fh:
            # read as bytes then decode fallback to handle b'...' weirdness
            raw = fh.read().decode('utf-8', errors='ignore').splitlines()
    except Exception:
        return {'dlls': dll_counter, 'functions': func_counter, 'num_imports': 0}

    for line in raw:
        s = line.strip()
        if not s:
            continue
        # dll lines typically end with .dll (case-insensitive)
        if s.lower().endswith('.dll'):
            current_dll = s.strip()
            dll_counter[current_dll] += 1
            continue
        # function lines often look like "b'FuncName'" or just "FuncName"
        # strip leading b' and trailing ' if present
        func = s
        # remove leading encoded byte prefix if present
        if func.startswith("b'") or func.startswith('b"'):
            func = func[2:]
        func = func.strip().strip("'\"")
        # remove any leading bytes-like garbage
        func = func.encode('utf-8', errors='ignore').decode('unicode_escape', errors='ignore')
        if func:
            func_counter[func] += 1
            num_funcs += 1

    return {'dlls': dll_counter, 'functions': func_counter, 'num_imports': num_funcs}


def parse_strings_file(path):
    """
    Read strings file and return list of strings, count, and suspicious keyword counts.
    """
    strings = []
    try:
        with open(path, 'rb') as fh:
            raw = fh.read().decode('utf-8', errors='ignore').splitlines()
    except Exception:
        return {'strings': [], 'num_strings': 0, 'keyword_counts': Counter()}

    for line in raw:
        s = line.rstrip('\n\r')
        if s:
            strings.append(s)
    keyword_counts = Counter()
    lowered = [s.lower() for s in strings]
    for kw in SUSPICIOUS_KEYWORDS:
        c = sum(1 for s in lowered if kw.lower() in s)
        if c:
            keyword_counts[kw] = c

    return {'strings': strings, 'num_strings': len(strings), 'keyword_counts': keyword_counts}


def parse_urls_file(path):
    """
    Collect unique URLs and domain counts.
    """
    urls = set()
    domains = Counter()
    try:
        with open(path, 'rb') as fh:
            raw = fh.read().decode('utf-8', errors='ignore')
    except Exception:
        return {'urls': set(), 'num_urls': 0, 'domains': domains}
    for m in RE_URL.finditer(raw):
        u = m.group(0)
        urls.add(u)
        # extract domain roughly
        try:
            domain = re.sub(r'^https?://', '', u, flags=re.IGNORECASE)
            domain = domain.split('/')[0].split(':')[0].lower()
            domains[domain] += 1
        except Exception:
            pass
    return {'urls': urls, 'num_urls': len(urls), 'domains': domains}


def parse_meta_file(path):
    """
    Parse meta file example block (multi-line). Extract:
      - size (int)
      - sha256 (hex)
      - basename
      - pe_type (PE32/PE32+)
      - sections (int)
      - compile_ts (int -> datetime)
    """
    info = {'size': None, 'sha256': None, 'basename': None, 'pe_type': None,
            'sections': None, 'compile_timestamp': None, 'filetype_line': None}
    try:
        with open(path, 'rb') as fh:
            raw = fh.read().decode('utf-8', errors='ignore')
    except Exception:
        return info

    # basename: look for the 'Processing ' line or file path lines
    m_proc = re.search(r'Processing\s+(.+)', raw)
    if m_proc:
        basepath = m_proc.group(1).strip()
        info['basename'] = os.path.basename(basepath)

    # filetype line (first line with PE/ELF)
    m_ft = RE_PE_TYPE.search(raw)
    if m_ft:
        info['pe_type'] = m_ft.group(0)

    # size
    m_size = RE_SIZE.search(raw)
    if m_size:
        try:
            info['size'] = int(m_size.group(1))
        except:
            pass

    # sections
    m_sec = RE_SECTIONS.search(raw)
    if m_sec:
        try:
            info['sections'] = int(m_sec.group(1))
        except:
            pass

    # sha256
    m_sha = RE_SHA256.search(raw)
    if m_sha:
        info['sha256'] = m_sha.group(1).lower()

    # compile timestamp
    m_cts = RE_COMPILE_TS.search(raw)
    if m_cts:
        try:
            ts = int(m_cts.group(1))
            info['compile_timestamp'] = ts
            # also convert to iso
            info['compile_iso'] = datetime.datetime.utcfromtimestamp(ts).isoformat() + 'Z'
        except:
            pass

    return info

def analyze_features(features_dir: Path, outdir: Path):
    features_dir = Path(features_dir)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # find samples by scanning meta files or listing unique prefixes
    meta_files = list(features_dir.glob('*.meta.txt'))
    # fallback: look for *.imports.txt and derive prefixes
    if not meta_files:
        prefixes = set(p.stem.replace('.meta','') for p in features_dir.glob('*.imports.txt'))
    else:
        prefixes = set(p.name.rsplit('.meta.txt',1)[0] for p in meta_files)

    rows = []
    agg_dlls = Counter()
    agg_funcs = Counter()
    agg_keywords = Counter()
    domain_counter = Counter()

    for prefix in sorted(prefixes):
        # derive file paths
        meta_p = features_dir / f"{prefix}.meta.txt"
        imports_p = features_dir / f"{prefix}.imports.txt"
        strings_p = features_dir / f"{prefix}.strings.txt"
        urls_p = features_dir / f"{prefix}.urls.txt"

        meta = parse_meta_file(meta_p) if meta_p.exists() else {}
        imports = parse_imports_file(imports_p) if imports_p.exists() else {'dlls': Counter(), 'functions': Counter(), 'num_imports': 0}
        strings = parse_strings_file(strings_p) if strings_p.exists() else {'strings': [], 'num_strings': 0, 'keyword_counts': Counter()}
        urls = parse_urls_file(urls_p) if urls_p.exists() else {'urls': set(), 'num_urls': 0, 'domains': Counter()}

        # derive label (benign/malicious) using path hints
        label = 'unknown'
        lowpref = prefix.lower()
        if '/benign/' in str(prefix).lower() or 'benign' in str(features_dir / prefix).lower():
            label = 'benign'
        elif '/malicious/' in str(prefix).lower() or 'malware' in str(features_dir / prefix).lower() or 'malicious' in str(features_dir / prefix).lower():
            label = 'malicious'
        else:
            # check parent directories names (if prefixes are full filenames with path included)
            # infer labels from the meta.txt files' basename
            b = meta.get('basename') or prefix
            if 'benign' in b.lower():
                label = 'benign'
            elif 'mal' in b.lower() or 'virus' in b.lower() or 'malware' in b.lower():
                label = 'malicious'

        row = {
            'sample': meta.get('basename') or prefix,
            'prefix': prefix,
            'label': label,
            'sha256': meta.get('sha256'),
            'size': meta.get('size'),
            'pe_type': meta.get('pe_type'),
            'sections': meta.get('sections'),
            'compile_ts': meta.get('compile_timestamp'),
            'compile_iso': meta.get('compile_iso', None),
            'num_imports': imports.get('num_imports', 0),
            'num_dlls': sum(1 for _ in imports.get('dlls',{}).elements()) if imports.get('dlls') else len(imports.get('dlls',[])),
            'num_funcs': sum(imports.get('functions', {}).values()),
            'num_strings': strings.get('num_strings', 0),
            'num_urls': urls.get('num_urls', 0),
            'top_domains': ';'.join([f"{d}:{c}" for d,c in urls.get('domains', {}).most_common(5)])
        }

        # aggregate
        agg_dlls.update(imports.get('dlls', Counter()))
        agg_funcs.update(imports.get('functions', Counter()))
        agg_keywords.update(strings.get('keyword_counts', Counter()))
        domain_counter.update(urls.get('domains', Counter()))

        rows.append(row)

    # dataframe and persist
    df = pd.DataFrame(rows)
    df.to_csv(outdir / 'summary.csv', index=False)
    print("Wrote:", outdir / 'summary.csv')

    # PLOTS 
    # Helper: separate labels
    labels = df['label'].fillna('unknown').unique().tolist()

    # histogram: num_imports by label
    plt.figure(figsize=(8,5))
    for lbl in labels:
        series = df.loc[df['label']==lbl, 'num_imports'].dropna()
        if series.size:
            plt.hist(series, bins=20, alpha=0.6, label=lbl)
    plt.xlabel('Number of imported functions')
    plt.ylabel('Count of samples')
    plt.title('Imported functions per sample (by label)')
    plt.legend()
    plt.tight_layout()
    plt.savefig(outdir / 'imports_histogram.png')
    plt.close()

    #  histogram: number of strings
    plt.figure(figsize=(8,5))
    for lbl in labels:
        series = df.loc[df['label']==lbl, 'num_strings'].dropna()
        if series.size:
            plt.hist(series, bins=30, alpha=0.6, label=lbl)
    plt.xlabel('Number of strings extracted')
    plt.ylabel('Count of samples')
    plt.title('Strings per sample (by label)')
    plt.legend()
    plt.tight_layout()
    plt.savefig(outdir / 'strings_histogram.png')
    plt.close()

    # top dlls bar chart
    top_dlls = agg_dlls.most_common(20)
    if top_dlls:
        names, counts = zip(*top_dlls)
        plt.figure(figsize=(10,6))
        plt.bar(range(len(names)), counts)
        plt.xticks(range(len(names)), names, rotation=45, ha='right')
        plt.ylabel('Occurrences (sum across samples)')
        plt.title('Top 20 imported DLLs')
        plt.tight_layout()
        plt.savefig(outdir / 'top_dlls.png')
        plt.close()

    # top functions bar chart
    top_funcs = agg_funcs.most_common(30)
    if top_funcs:
        names, counts = zip(*top_funcs)
        plt.figure(figsize=(12,6))
        plt.bar(range(len(names)), counts)
        plt.xticks(range(len(names)), names, rotation=90, ha='right')
        plt.ylabel('Occurrences (sum across samples)')
        plt.title('Top imported functions (top 30)')
        plt.tight_layout()
        plt.savefig(outdir / 'top_functions.png')
        plt.close()

    # suspicious keywords bar chart
    top_keywords = agg_keywords.most_common()
    if top_keywords:
        names, counts = zip(*top_keywords)
        plt.figure(figsize=(10,4))
        plt.bar(range(len(names)), counts)
        plt.xticks(range(len(names)), names, rotation=45, ha='right')
        plt.ylabel('Match counts across dataset')
        plt.title('Suspicious keyword hits (strings)')
        plt.tight_layout()
        plt.savefig(outdir / 'suspicious_keywords.png')
        plt.close()

    # urls per sample histogram
    plt.figure(figsize=(8,5))
    series = df['num_urls'].dropna()
    if series.size:
        plt.hist(series, bins=20)
        plt.xlabel('Number of unique URLs per sample')
        plt.ylabel('Count of samples')
        plt.title('URLs found per sample')
        plt.tight_layout()
        plt.savefig(outdir / 'urls_per_sample.png')
        plt.close()

    # Save aggregated JSON summary
    out_json = {
        'top_dlls': agg_dlls.most_common(200),
        'top_funcs': agg_funcs.most_common(200),
        'top_keywords': agg_keywords.most_common(200),
        'top_domains': domain_counter.most_common(200),
        'summary_rows': rows
    }
    with open(outdir / 'top_items.json', 'w') as fh:
        json.dump(out_json, fh, indent=2)

    print("Plots and JSON summary written to", outdir)

def main():
    parser = argparse.ArgumentParser(description="Analyze features folder and produce plots.")
    parser.add_argument('--features-dir', '-f', required=True, help='Path to features directory')
    parser.add_argument('--outdir', '-o', default='out', help='Output directory for CSV/PNGs')
    args = parser.parse_args()
    analyze_features(Path(args.features_dir), Path(args.outdir))

if __name__ == '__main__':
    main()

