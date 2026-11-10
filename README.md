# RowSentry

**Audit a CSV file against the contract the file itself implies.**

Every tabular file carries an implied contract: the header names the
columns, the rows agree on a width, and each column settles into a
type. RowSentry reads that contract out of the file and reports every
place the file breaks its own rules — ragged rows, duplicate or blank
headers, duplicate rows, duplicate keys, cells that drift from their
column's type, and quoting errors — with record numbers you can act
on. One Python file, no dependencies, no network, read-only: the file
is never modified.

```
$ rowsentry check export.csv --key id
file: export.csv
delimiter: ,
columns: 3 (id, name, score)
data rows: 6
finding: [error] duplicate-key record 4: key '7' also appears at record 2
finding: [warning] type-drift record 7: score: cell 'N/A' is text, column is dominantly int
rowsentry: 6 rows, 1 errors, 1 warnings
```

## Why it's different

- **No schema, no stack.** Established validators want a schema to
  check against, a Ruby or JVM runtime, or a framework install.
  RowSentry infers the contract from the file itself — header,
  majority width, and per-column dominant type — so the check runs
  anywhere Python 3.10+ runs, on files whose schema nobody wrote down.
- **Duplicate keys, not just duplicate rows.** An exact duplicate row
  is the easy corruption. The silent one is the same key appearing
  twice with *different* payloads — a re-import, a botched merge.
  Name the key column with `--key` and that becomes an error.
- **Type drift is a finding.** A text cell in a numeric column, a
  float in an integer column, an impossible date in a date column —
  reported by record number. Drift is only called when a column is
  genuinely settled (at least 5 non-empty cells, one type holding at
  least 80%), so honestly mixed columns stay quiet, and integers are
  always accepted in float columns.
- **A gate, not a viewer.** Exit codes are the interface: 0 clean,
  1 error findings, 2 the check could not run. Findings are counted
  exactly even when examples are capped, and `--json` output is
  byte-deterministic for a fixed input, so the verdict drops into a
  pre-import or pre-commit script unchanged.

## Install

Download `rowsentry.py` and run it with Python 3.10 or newer.
That's the whole installation.

## Usage

```
rowsentry check FILE [--delimiter X] [--no-header] [--key COL]
                     [--max-examples N] [--json]
rowsentry --version
```

- `check` audits one CSV/TSV file. The delimiter is sniffed among
  comma, semicolon, tab, and pipe unless `--delimiter` pins it
  (a single character, or `\t` for tab).
- `--no-header` treats the first row as data; the expected width is
  that row's width, and `--key` then takes a 1-based column number.
- `--key COL` names the column whose values must be unique and
  non-empty across data rows.
- `--max-examples N` caps the example findings printed per code
  (default 10); totals in the summary and in `--json` counts are
  always exact.
- Record numbers count parsed records starting at 1, header
  included — a quoted field containing newlines is one record, so a
  record number is not always a physical line number.
- Input is read as UTF-8 (a byte-order mark is tolerated; invalid
  UTF-8 is an exit-2 error, never a silent guess).

### How types are decided

Each cell is classified in a fixed order — empty, bool (`true` /
`false`), int, float, date (`YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SS`,
optional trailing `Z`), text. A column's dominant type is the most
common class among its non-empty cells. That is the whole inference:
documented, deterministic, and identical on every run.

### Findings

| Code | Severity | Meaning |
|---|---|---|
| `empty-file` | error | The file contains no records |
| `duplicate-header` | error | A header name appears more than once |
| `blank-header` | error | A column has a blank header name |
| `ragged-row` | error | A row's width differs from the expected width |
| `duplicate-key` | error | A `--key` value appears in more than one data row |
| `parse-error` | error | Strict CSV parsing failed (e.g. an unclosed quote) |
| `no-data-rows` | warning | A header exists but there are no data rows |
| `duplicate-row` | warning | A row exactly duplicates an earlier row |
| `empty-key` | warning | A data row's key cell is empty |
| `empty-column` | warning | A column is empty in every data row |
| `type-drift` | warning | A cell's type differs from its column's dominant type |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | The check ran and found no error findings |
| 1 | Error findings are present |
| 2 | Usage or I/O error (missing file, invalid UTF-8, bad options, unknown `--key` column) |

That contract makes RowSentry a gate in any script:

```
rowsentry check incoming.csv --key id || echo "import blocked — see findings"
```

## Limitations, stated honestly

- RowSentry checks a file against *itself*. It cannot know that a
  column should be a date, or that a key should exist in another
  file — cross-file and schema checks belong to schema validators,
  which are the right tool when a real schema exists.
- Type inference is deliberately small: five classes, two date
  shapes. Locale dates (`31/12/2026`), currency symbols, and
  thousands separators classify as text — in a column of the same
  shapes they agree with each other and stay quiet; mixed into an
  ISO-date or plain-number column they are reported as drift, which
  is usually the point.
- Duplicate detection is exact: two rows that differ only in
  whitespace or letter case are different rows here.
- The whole file is read into memory. That is the right trade for
  import-sized files; it is not a tool for multi-gigabyte streams.

## License

MIT — see `LICENSE`. A Dimon Global Group release.
