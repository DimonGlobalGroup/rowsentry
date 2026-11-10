"""RowSentry test suite — stdlib unittest only.

Run: python3 -m unittest test_rowsentry -v
"""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "rowsentry.py"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True, text=True, timeout=30)


class RowSentryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text, encoding="utf-8"):
        p = self.dir / name
        p.write_text(text, encoding=encoding)
        return str(p)

    def report(self, *args):
        proc = run_cli("check", *args, "--json")
        return proc, json.loads(proc.stdout)

    # -- clean files -------------------------------------------------
    def test_clean_file_exit_zero(self):
        path = self.write("ok.csv", "id,name\n1,alpha\n2,beta\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(rep["errors"], 0)
        self.assertEqual(rep["data_rows"], 2)

    def test_bom_tolerated(self):
        p = self.dir / "bom.csv"
        p.write_bytes(b"\xef\xbb\xbfid,name\n1,alpha\n")
        proc, rep = self.report(str(p))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(rep["columns"], ["id", "name"])

    def test_semicolon_sniffed(self):
        path = self.write("semi.csv", "id;name\n1;alpha\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(rep["delimiter"], ";")

    def test_explicit_tab_delimiter(self):
        path = self.write("tab.tsv", "id\tname\n1\talpha\n")
        proc, rep = self.report(path, "--delimiter", r"\t")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(rep["delimiter"], "\t")

    def test_quoted_newline_is_one_record(self):
        path = self.write(
            "q.csv", 'id,note\n1,"line one\nline two"\n2,plain\n')
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(rep["data_rows"], 2)

    # -- structural findings ------------------------------------------
    def test_ragged_row_is_error(self):
        path = self.write("rag.csv", "a,b,c\n1,2,3\n4,5\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 1)
        codes = [f["code"] for f in rep["findings"]]
        self.assertIn("ragged-row", codes)
        rag = [f for f in rep["findings"] if f["code"] == "ragged-row"]
        self.assertEqual(rag[0]["record"], 3)

    def test_duplicate_header_is_error(self):
        path = self.write("dup.csv", "id,name,id\n1,x,2\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("duplicate-header",
                      [f["code"] for f in rep["findings"]])

    def test_blank_header_is_error(self):
        path = self.write("blank.csv", "id,,name\n1,2,3\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("blank-header",
                      [f["code"] for f in rep["findings"]])

    def test_empty_file_is_error(self):
        path = self.write("empty.csv", "")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("empty-file",
                      [f["code"] for f in rep["findings"]])

    def test_header_only_warns_not_errors(self):
        path = self.write("hdr.csv", "a,b\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("no-data-rows",
                      [f["code"] for f in rep["findings"]])

    def test_unclosed_quote_is_parse_error(self):
        path = self.write("bad.csv", 'a,b\n1,"never closed\n')
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("parse-error",
                      [f["code"] for f in rep["findings"]])

    # -- duplicates ----------------------------------------------------
    def test_duplicate_row_warns(self):
        path = self.write("duprow.csv", "a,b\n1,x\n2,y\n1,x\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        dups = [f for f in rep["findings"]
                if f["code"] == "duplicate-row"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["record"], 4)

    def test_duplicate_key_is_error(self):
        path = self.write(
            "key.csv", "id,val\n7,one\n8,two\n7,three\n")
        proc, rep = self.report(path, "--key", "id")
        self.assertEqual(proc.returncode, 1)
        dups = [f for f in rep["findings"]
                if f["code"] == "duplicate-key"]
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["record"], 4)

    def test_same_key_same_row_is_not_key_error_alone(self):
        # An exact duplicate row under --key yields duplicate-row AND
        # duplicate-key; pin the key finding's presence either way.
        path = self.write("key2.csv", "id,val\n7,one\n7,one\n")
        proc, rep = self.report(path, "--key", "id")
        self.assertEqual(proc.returncode, 1)

    def test_unknown_key_column_exit_two(self):
        path = self.write("key3.csv", "id,val\n7,one\n")
        proc = run_cli("check", path, "--key", "nope")
        self.assertEqual(proc.returncode, 2)

    def test_empty_key_warns(self):
        path = self.write("key4.csv", "id,val\n,one\n8,two\n")
        proc, rep = self.report(path, "--key", "id")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("empty-key",
                      [f["code"] for f in rep["findings"]])

    def test_key_by_number_no_header(self):
        path = self.write("nh.csv", "7,one\n7,two\n", )
        proc, rep = self.report(path, "--no-header", "--key", "1")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("duplicate-key",
                      [f["code"] for f in rep["findings"]])

    # -- type drift ------------------------------------------------------
    def test_type_drift_text_in_int_column(self):
        rows = "\n".join(str(i) for i in range(1, 10))
        path = self.write("drift.csv", f"n\n{rows}\nN/A\n")
        proc, rep = self.report(path)
        self.assertEqual(proc.returncode, 0)
        drift = [f for f in rep["findings"]
                 if f["code"] == "type-drift"]
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0]["record"], 11)

    def test_int_cells_ok_in_float_column(self):
        vals = ["1.5", "2.5", "3.5", "4.5", "5.5", "6"]
        path = self.write("float.csv", "x\n" + "\n".join(vals) + "\n")
        proc, rep = self.report(path)
        self.assertNotIn("type-drift",
                         [f["code"] for f in rep["findings"]])

    def test_float_in_int_column_drifts(self):
        vals = ["1", "2", "3", "4", "5", "6", "7", "8", "2.5"]
        path = self.write("int.csv", "x\n" + "\n".join(vals) + "\n")
        proc, rep = self.report(path)
        drift = [f for f in rep["findings"]
                 if f["code"] == "type-drift"]
        self.assertEqual(len(drift), 1)

    def test_mixed_column_stays_quiet(self):
        vals = ["1", "one", "2", "two", "3", "three", "4", "four"]
        path = self.write("mix.csv", "x\n" + "\n".join(vals) + "\n")
        proc, rep = self.report(path)
        self.assertNotIn("type-drift",
                         [f["code"] for f in rep["findings"]])

    def test_small_column_stays_quiet(self):
        path = self.write("small.csv", "x\n1\n2\nN/A\n")
        proc, rep = self.report(path)
        self.assertNotIn("type-drift",
                         [f["code"] for f in rep["findings"]])

    def test_broken_date_drifts_in_date_column(self):
        vals = ["2026-01-01", "2026-01-02", "2026-01-03",
                "2026-01-04", "2026-01-05", "2026-13-45"]
        path = self.write("date.csv", "d\n" + "\n".join(vals) + "\n")
        proc, rep = self.report(path)
        drift = [f for f in rep["findings"]
                 if f["code"] == "type-drift"]
        self.assertEqual(len(drift), 1)

    def test_empty_column_warns(self):
        path = self.write("ec.csv", "a,b\n1,\n2,\n")
        proc, rep = self.report(path)
        self.assertIn("empty-column",
                      [f["code"] for f in rep["findings"]])

    # -- modes, caps, determinism, errors --------------------------------
    def test_no_header_mode(self):
        path = self.write("nh2.csv", "1,x\n2,y\n3\n")
        proc, rep = self.report(path, "--no-header")
        self.assertEqual(proc.returncode, 1)
        self.assertIsNone(rep["columns"])
        self.assertIn("ragged-row",
                      [f["code"] for f in rep["findings"]])

    def test_examples_capped_but_counted(self):
        body = "a,b\n" + "".join("1\n" for _ in range(15))
        path = self.write("many.csv", body)
        proc, rep = self.report(path, "--max-examples", "3")
        self.assertEqual(rep["counts"]["error:ragged-row"], 15)
        shown = [f for f in rep["findings"]
                 if f["code"] == "ragged-row"]
        self.assertEqual(len(shown), 3)

    def test_json_deterministic(self):
        path = self.write("det.csv", "a,b\n1,x\n1,x\n")
        first = run_cli("check", path, "--json")
        second = run_cli("check", path, "--json")
        self.assertEqual(first.stdout, second.stdout)

    def test_missing_file_exit_two(self):
        proc = run_cli("check", str(self.dir / "nope.csv"))
        self.assertEqual(proc.returncode, 2)

    def test_invalid_utf8_exit_two(self):
        p = self.dir / "bin.csv"
        p.write_bytes(b"a,b\n1,\xff\xfe\n")
        proc = run_cli("check", str(p))
        self.assertEqual(proc.returncode, 2)

    def test_text_output_summary(self):
        path = self.write("txt.csv", "a,b\n1,x\n")
        proc = run_cli("check", path)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("rowsentry: 1 rows, 0 errors, 0 warnings",
                      proc.stdout)

    def test_version(self):
        proc = run_cli("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)


if __name__ == "__main__":
    unittest.main()
