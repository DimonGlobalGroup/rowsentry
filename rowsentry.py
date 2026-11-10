#!/usr/bin/env python3
"""RowSentry — audit a CSV/TSV file against the contract it implies.

Single-file, stdlib-only, read-only. See README.md.
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from datetime import datetime

__version__ = "1.0.0"

_INT_RE = re.compile(r"^[+-]?\d+$")
_FLOAT_RE = re.compile(r"^[+-]?(\d+\.\d*|\.\d+|\d+)([eE][+-]?\d+)?$")
_DATE_FORMATS = ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S")


def classify(cell):
    """Deterministic cell type: empty|bool|int|float|date|text."""
    s = cell.strip()
    if not s:
        return "empty"
    if s.lower() in ("true", "false"):
        return "bool"
    if _INT_RE.match(s):
        return "int"
    if _FLOAT_RE.match(s):
        try:
            float(s)
            return "float"
        except ValueError:
            pass
    candidate = s[:-1] if s.endswith("Z") else s
    for fmt in _DATE_FORMATS:
        try:
            datetime.strptime(candidate, fmt)
            return "date"
        except ValueError:
            continue
    return "text"


def _compatible(cell_type, dominant):
    if cell_type == dominant:
        return True
    # An integer is a valid value in a float column.
    return dominant == "float" and cell_type == "int"


class Findings:
    def __init__(self, max_examples):
        self.max_examples = max_examples
        self.items = []          # example findings, in scan order
        self.counts = Counter()  # (severity, code) -> total
        self._seen = Counter()   # code -> examples kept so far

    def add(self, severity, code, record, message):
        self.counts[(severity, code)] += 1
        if self._seen[code] < self.max_examples:
            self._seen[code] += 1
            self.items.append({
                "severity": severity,
                "code": code,
                "record": record,
                "message": message,
            })

    @property
    def errors(self):
        return sum(n for (sev, _), n in self.counts.items()
                   if sev == "error")

    @property
    def warnings(self):
        return sum(n for (sev, _), n in self.counts.items()
                   if sev == "warning")


def sniff_delimiter(sample):
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except csv.Error:
        return ","


def resolve_delimiter(raw):
    if raw is None:
        return None
    if raw == r"\t":
        return "\t"
    if len(raw) != 1:
        raise ValueError("--delimiter must be a single character (or \\t)")
    return raw


def check_file(path, delimiter_opt, no_header, key_opt, max_examples):
    """Returns (report_dict, exit_code). Raises OSError/UnicodeDecodeError
    and ValueError for usage-level problems handled by the caller."""
    findings = Findings(max_examples)
    with open(path, "r", encoding="utf-8-sig", newline="") as fh:
        sample = fh.read(8192)
        fh.seek(0)
        delimiter = delimiter_opt or sniff_delimiter(sample)
        reader = csv.reader(fh, delimiter=delimiter, strict=True)
        rows = []
        parse_failed = False
        try:
            for row in reader:
                rows.append(row)
        except csv.Error as exc:
            findings.add("error", "parse-error", reader.line_num,
                         f"strict CSV parse failed: {exc}")
            parse_failed = True

    if not rows and not parse_failed:
        findings.add("error", "empty-file", None,
                     "file contains no records")
        report = _report(path, delimiter, [], 0, findings)
        return report, 1 if findings.errors else 0

    if no_header:
        header = None
        data = rows
        first_record = 1
        width = len(rows[0]) if rows else 0
        key_index = None
        if key_opt is not None:
            try:
                key_index = int(key_opt) - 1
            except ValueError:
                raise ValueError(
                    "--key under --no-header must be a 1-based "
                    "column number")
            if key_index < 0 or key_index >= width:
                raise ValueError(f"--key column {key_opt} is out of range")
    else:
        header = rows[0] if rows else []
        data = rows[1:] if rows else []
        first_record = 2
        width = len(header)
        # Header findings.
        seen_names = {}
        for idx, name in enumerate(header):
            stripped = name.strip()
            if not stripped:
                findings.add("error", "blank-header", 1,
                             f"column {idx + 1} has a blank header")
            elif stripped in seen_names:
                findings.add(
                    "error", "duplicate-header", 1,
                    f"header {stripped!r} appears at columns "
                    f"{seen_names[stripped] + 1} and {idx + 1}")
            else:
                seen_names[stripped] = idx
        key_index = None
        if key_opt is not None:
            if key_opt not in header:
                raise ValueError(
                    f"--key column {key_opt!r} not found in header")
            key_index = header.index(key_opt)
        if not data and not parse_failed:
            findings.add("warning", "no-data-rows", None,
                         "file has a header but no data rows")

    # Ragged rows + duplicate rows + keys.
    seen_rows = {}
    seen_keys = {}
    for offset, row in enumerate(data):
        record = first_record + offset
        if len(row) != width:
            findings.add("error", "ragged-row", record,
                         f"row has {len(row)} fields, expected {width}")
        digest = hashlib.sha256(
            "\x1f".join(row).encode("utf-8")).hexdigest()
        if digest in seen_rows:
            findings.add("warning", "duplicate-row", record,
                         f"row is an exact duplicate of record "
                         f"{seen_rows[digest]}")
        else:
            seen_rows[digest] = record
        if key_index is not None and len(row) > key_index:
            key_value = row[key_index]
            if not key_value.strip():
                findings.add("warning", "empty-key", record,
                             "key cell is empty")
            elif key_value in seen_keys:
                findings.add("error", "duplicate-key", record,
                             f"key {key_value!r} also appears at "
                             f"record {seen_keys[key_value]}")
            else:
                seen_keys[key_value] = record

    # Per-column checks (well-formed rows only).
    if width:
        for col in range(width):
            cells = [(first_record + off, row[col])
                     for off, row in enumerate(data) if len(row) == width]
            types = [classify(c) for _, c in cells]
            non_empty = [(rec, c, t) for (rec, c), t in zip(cells, types)
                         if t != "empty"]
            label = (header[col].strip() if header and header[col].strip()
                     else f"column {col + 1}")
            if data and not non_empty:
                findings.add("warning", "empty-column", None,
                             f"{label} is empty in every data row")
                continue
            if len(non_empty) < 5:
                continue
            counts = Counter(t for _, _, t in non_empty)
            dominant, dominant_n = counts.most_common(1)[0]
            if dominant_n / len(non_empty) < 0.8:
                continue
            for rec, cell, t in non_empty:
                if not _compatible(t, dominant):
                    findings.add(
                        "warning", "type-drift", rec,
                        f"{label}: cell {cell.strip()!r} is {t}, "
                        f"column is dominantly {dominant}")

    report = _report(path, delimiter, header, len(data), findings)
    return report, 1 if findings.errors else 0


def _report(path, delimiter, header, row_count, findings):
    return {
        "file": path,
        "delimiter": delimiter,
        "columns": header,
        "data_rows": row_count,
        "errors": findings.errors,
        "warnings": findings.warnings,
        "counts": {f"{sev}:{code}": n
                   for (sev, code), n in sorted(findings.counts.items())},
        "findings": findings.items,
    }


def render_text(report):
    lines = []
    delim = report["delimiter"]
    delim_label = {"\t": "tab"}.get(delim, delim)
    cols = report["columns"]
    lines.append(f"file: {report['file']}")
    lines.append(f"delimiter: {delim_label}")
    if cols is not None:
        lines.append(f"columns: {len(cols)} ({', '.join(cols)})")
    lines.append(f"data rows: {report['data_rows']}")
    totals = {}
    for key, n in report["counts"].items():
        totals[key] = n
    shown = Counter()
    for f in report["findings"]:
        shown[f["code"]] += 1
        where = f"record {f['record']}: " if f["record"] else ""
        lines.append(f"finding: [{f['severity']}] {f['code']} "
                     f"{where}{f['message']}")
    for key, total in sorted(totals.items()):
        _, code = key.split(":", 1)
        extra = total - shown.get(code, 0)
        if extra > 0:
            lines.append(f"finding: ... and {extra} more {code} "
                         f"finding(s) not shown")
    lines.append(f"rowsentry: {report['data_rows']} rows, "
                 f"{report['errors']} errors, {report['warnings']} warnings")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="rowsentry",
        description="Audit a CSV/TSV file against the contract "
                    "the file itself implies.")
    ap.add_argument("--version", action="version",
                    version=f"rowsentry {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    chk = sub.add_parser("check", help="check one CSV/TSV file")
    chk.add_argument("file")
    chk.add_argument("--delimiter", default=None,
                     help="single character or \\t (default: sniff)")
    chk.add_argument("--no-header", action="store_true",
                     help="file has no header row")
    chk.add_argument("--key", default=None,
                     help="header name (or 1-based column number "
                          "with --no-header) that must be unique")
    chk.add_argument("--max-examples", type=int, default=10,
                     help="max example findings per code (default 10)")
    chk.add_argument("--json", action="store_true",
                     help="emit the report as JSON")
    args = ap.parse_args(argv)

    if args.max_examples < 0:
        print("rowsentry: --max-examples must be >= 0", file=sys.stderr)
        return 2
    try:
        delimiter = resolve_delimiter(args.delimiter)
    except ValueError as exc:
        print(f"rowsentry: {exc}", file=sys.stderr)
        return 2
    try:
        report, code = check_file(
            args.file, delimiter, args.no_header, args.key,
            args.max_examples)
    except FileNotFoundError:
        print(f"rowsentry: no such file: {args.file}", file=sys.stderr)
        return 2
    except (OSError, UnicodeDecodeError) as exc:
        print(f"rowsentry: cannot read {args.file}: {exc}",
              file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"rowsentry: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_text(report))
    return code


if __name__ == "__main__":
    sys.exit(main())
