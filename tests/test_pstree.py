"""Run the actual pstree.c against synthetic ptree results (host GCC required)."""
import collections
import ctypes
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NPROC = 64
LINE = re.compile(
    r"^( *)(.*?) \(pid=(-?\d+), ppid=(-?\d+), state=(-?\d+), mem=(\d+) bytes\)$"
)


class Record(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_int), ("ppid", ctypes.c_int),
                ("state", ctypes.c_int), ("memsize", ctypes.c_ulong),
                ("name", ctypes.c_char * 16)]


def record(pid, ppid, name, state=2, memsize=4096):
    return Record(pid, ppid, state, memsize, name.encode())


def parse_output(output):
    result = []
    for line in output.splitlines():
        match = LINE.fullmatch(line)
        if not match:
            raise AssertionError(f"Invalid output line: {line!r}")
        spaces, name, pid, ppid, state, memory = match.groups()
        if len(spaces) % 2:
            raise AssertionError("Indentation must use multiples of two spaces")
        result.append({"depth": len(spaces) // 2, "name": name,
                       "pid": int(pid), "ppid": int(ppid),
                       "state": int(state), "memsize": int(memory)})
    return result


HARNESS = r'''
#include <stdarg.h>
#include <setjmp.h>
// Function-like macros preserve the bare printf archetype in format attributes.
#define printf(...) test_printf(__VA_ARGS__)
#define fprintf(...) test_fprintf(__VA_ARGS__)
#define exit(...) test_exit(__VA_ARGS__)
#define ptree(...) test_ptree(__VA_ARGS__)
#define main pstree_program
#include @SOURCE@
#undef main
#undef ptree
#undef exit
#undef fprintf
#undef printf

extern int vsnprintf(char *, __SIZE_TYPE__, const char *, va_list);
static jmp_buf jump;
static struct ptreeinfo fixture[NPROC];
static int fixture_count, syscall_result, calls, last_max, exit_status;
static char output[65536], errors[1024];
static int output_used, errors_used;

static void append(char *dst, int *used, int size, const char *fmt, va_list ap)
{
  int n = vsnprintf(dst + *used, size - *used, fmt, ap);
  if(n < 0 || n >= size - *used)
    test_exit(99);
  *used += n;
}

void test_printf(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  append(output, &output_used, sizeof(output), fmt, ap);
  va_end(ap);
}

void test_fprintf(int fd, const char *fmt, ...)
{
  if(fd != 2)
    test_exit(99);
  va_list ap;
  va_start(ap, fmt);
  append(errors, &errors_used, sizeof(errors), fmt, ap);
  va_end(ap);
}

int test_exit(int status)
{
  exit_status = status;
  longjmp(jump, 1);
}

int test_ptree(struct ptreeinfo *dst, int max)
{
  calls++;
  last_max = max;
  for(int i = 0; i < fixture_count && i < max; i++)
    dst[i] = fixture[i];
  return syscall_result;
}

int pstree_test_run(const struct ptreeinfo *items, int length, int result)
{
  if(length < 0 || length > NPROC)
    return 99;
  fixture_count = length;
  syscall_result = result;
  calls = last_max = output_used = errors_used = 0;
  output[0] = errors[0] = 0;
  exit_status = 99;
  for(int i = 0; i < length; i++)
    fixture[i] = items[i];
  if(setjmp(jump) == 0)
    pstree_program();
  return exit_status;
}

const char *pstree_test_output(void) { return output; }
const char *pstree_test_errors(void) { return errors; }
int pstree_test_calls(void) { return calls; }
int pstree_test_max(void) { return last_max; }
'''


class PstreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="pstree-unit-")
        directory = Path(cls.temp.name)
        source = directory / "harness.c"
        library = directory / "pstree.so"
        source.write_text(HARNESS.replace("@SOURCE@", json.dumps(str(ROOT / "user/pstree.c"))))
        subprocess.run(["gcc", "-std=c11", "-Wall", "-Werror", "-fno-builtin",
                        "-shared", "-fPIC", "-I", str(ROOT), str(source),
                        "-o", str(library)], check=True)
        cls.lib = ctypes.CDLL(str(library))
        cls.lib.pstree_test_run.argtypes = [ctypes.POINTER(Record), ctypes.c_int, ctypes.c_int]
        cls.lib.pstree_test_run.restype = ctypes.c_int
        for name in ("pstree_test_output", "pstree_test_errors"):
            getattr(cls.lib, name).restype = ctypes.c_char_p

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_fixture(self, records, result=None):
        array = (Record * len(records))(*records)
        status = self.lib.pstree_test_run(array, len(records),
                                         len(records) if result is None else result)
        output = self.lib.pstree_test_output().decode()
        errors = self.lib.pstree_test_errors().decode()
        self.assertEqual(self.lib.pstree_test_calls(), 1)
        self.assertEqual(self.lib.pstree_test_max(), NPROC)
        return status, output, errors

    def check_conservation(self, records, output):
        lines = parse_output(output)
        expected = collections.Counter(
            (r.pid, r.ppid, r.state, r.memsize, r.name.decode() or "(unnamed)")
            for r in records)
        actual = collections.Counter(
            (r["pid"], r["ppid"], r["state"], r["memsize"], r["name"])
            for r in lines)
        self.assertEqual(actual, expected)
        ancestors = []
        for row in lines:
            depth = row["depth"]
            self.assertLessEqual(depth, len(ancestors))
            self.assertLess(depth, max(1, len(records)))
            if depth:
                self.assertEqual(row["ppid"], ancestors[depth - 1]["pid"])
                self.assertGreater(row["pid"], 0)
                self.assertGreater(row["ppid"], 0)
                self.assertNotEqual(row["pid"], row["ppid"])
            ancestors = ancestors[:depth] + [row]
        return lines

    def test_exact_tree_order_and_large_memory(self):
        items = [record(12, 7, "grand"), record(1500, 900, "sibling"),
                 record(900, 41, "shell"), record(7, 900, "worker", 4, 2**32 + 123),
                 record(41, 0, "root")]
        status, output, errors = self.run_fixture(items)
        self.assertEqual((status, errors), (0, ""))
        rows = self.check_conservation(items, output)
        self.assertEqual([(r["pid"], r["depth"]) for r in rows],
                         [(41, 0), (900, 1), (7, 2), (12, 3), (1500, 2)])

    def test_permutations_have_identical_output(self):
        items = [record(80, 900, "a"), record(900, 0, "root"),
                 record(70000, 80, "b"), record(7, 900, "c"), record(66, 999, "orphan")]
        reference = self.run_fixture(items)[1]
        rng = random.Random(5)
        for _ in range(32):
            rng.shuffle(items)
            status, output, errors = self.run_fixture(items)
            self.assertEqual((status, errors, output), (0, "", reference))
            self.check_conservation(items, output)

    def test_missing_parent_forest_and_empty_name(self):
        items = [record(40, 987654, ""), record(10, 0, "root"),
                 record(41, 40, "leaf"), record(70, 0, "other")]
        status, output, errors = self.run_fixture(items)
        self.assertEqual((status, errors), (0, ""))
        rows = self.check_conservation(items, output)
        self.assertEqual([(r["pid"], r["depth"]) for r in rows],
                         [(10, 0), (40, 0), (41, 1), (70, 0)])

    def test_invalid_and_duplicate_identifiers(self):
        items = [record(-7, 10, "negative"), record(0, 10, "zero"),
                 record(10, -2, "badparent"), record(30, 30, "self"),
                 record(31, 30, "child"), record(50, 10, "dupA"),
                 record(50, 10, "dupB"), record(60, 50, "ambiguous")]
        status, output, errors = self.run_fixture(items)
        self.assertEqual((status, errors), (0, ""))
        rows = self.check_conservation(items, output)
        self.assertEqual({r["name"]: r["depth"] for r in rows},
                         {r.name.decode(): 1 if r.pid == 31 else 0 for r in items})

    def test_cycles_with_descendants(self):
        items = [record(60, 50, "leaf"), record(50, 40, "b"), record(40, 50, "a"),
                 record(70, 80, "c"), record(80, 90, "d"), record(90, 70, "e")]
        status, output, errors = self.run_fixture(items)
        self.assertEqual((status, errors), (0, ""))
        rows = self.check_conservation(items, output)
        self.assertEqual([(r["pid"], r["depth"]) for r in rows],
                         [(40, 0), (50, 1), (60, 2), (70, 0), (90, 1), (80, 2)])

    def test_maximum_chain(self):
        items = [record(100000 + i, 0 if i == 0 else 99999 + i, f"p{i}")
                 for i in range(NPROC)]
        status, output, errors = self.run_fixture(list(reversed(items)))
        self.assertEqual((status, errors), (0, ""))
        rows = self.check_conservation(items, output)
        self.assertEqual([r["depth"] for r in rows], list(range(NPROC)))

    def test_unterminated_name_is_bounded(self):
        items = [record(77, 0, "x" * 16, 123)]
        status, output, errors = self.run_fixture(items)
        self.assertEqual((status, errors), (0, ""))
        self.check_conservation(items, output)

    def test_empty_snapshot(self):
        self.assertEqual(self.run_fixture([]), (0, "", ""))

    def test_syscall_error(self):
        status, output, errors = self.run_fixture([record(1, 0, "ignored")], -1)
        self.assertEqual((status, output), (1, ""))
        self.assertIn("ptree failed", errors)

    def test_invalid_counts(self):
        for count in (-2, NPROC + 1, 2**31 - 1):
            with self.subTest(count=count):
                status, output, errors = self.run_fixture([record(1, 0, "ignored")], count)
                self.assertEqual((status, output), (1, ""))
                self.assertIn("invalid record count", errors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
