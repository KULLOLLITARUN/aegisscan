"""Tree-sitter JS/TS optimizer rules (OPT001-OPT004 ports)."""
from __future__ import annotations

from pathlib import Path

import pytest

from scanner.static_analysis import optimization_js
from scanner.static_analysis.optimization_runner import run_optimizer

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _scan(tmp_path: Path, body: str, name: str = "m.js"):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return run_optimizer(tmp_path)


def _loop(stmt: str, header: str = "for (const it of items)") -> str:
    return f"async function f(items) {{\n  {header} {{\n    {stmt}\n  }}\n}}\n"


# ------------------------------------------------------------------ fixtures / benchmark
def test_slow_js_fixture_flags_each_rule_once() -> None:
    findings = run_optimizer(EXAMPLES / "slow_js")
    issues = sorted(f.issue_type.split(" (")[0] for f in findings)
    assert issues == [
        "Database call inside loop",
        "Database call inside loop",
        "Nested loop over same collection",
        "Network call inside loop",
        "Regex pattern re-resolved in loop",
        "String concatenation in loop",
    ]
    assert all(f.rule_source == "aegis-opt" and f.category == "performance" for f in findings)
    assert all(f.file_path.suffix == ".js" for f in findings)


def test_tricky_clean_js_has_no_false_positives() -> None:
    assert run_optimizer(EXAMPLES / "tricky_clean_js") == []


def test_existing_js_examples_unaffected() -> None:
    for name in ("vulnerable_js",):
        assert run_optimizer(EXAMPLES / name) == [], name


# ------------------------------------------------------------------ OPT001 db / network
@pytest.mark.parametrize(
    "stmt,kind",
    [
        ("await db.query('select 1');", "Database"),
        ("await pool.execute('select 1');", "Database"),
        ("await User.findById(it);", "Database"),
        ("await Post.findAll({ where: { id: it } });", "Database"),
        ("await prisma.user.findMany({ where: { id: it } });", "Database"),
        ("await this.userRepository.findOne({ id: it });", "Database"),
        ("await knex('users').where({ id: it }).first();", "Database"),
        ("await fetch(`/api/${it}`);", "Network"),
        ("await axios.get(url);", "Network"),
        ("const r = await axios.post(endpoint, it);", "Network"),
        ("await apiClient.get(`/x/${it}`);", "Network"),
        ("await $.ajax({ url: it });", "Network"),
    ],
)
def test_flags_round_trip_in_loop(tmp_path: Path, stmt: str, kind: str) -> None:
    findings = _scan(tmp_path, _loop(stmt))
    assert len(findings) == 1, stmt
    assert findings[0].issue_type.startswith(f"{kind} call inside loop")


@pytest.mark.parametrize(
    "stmt",
    [
        "cache.get(it);",
        "session.get('user');",
        "parser.query(it);",
        "map.get(it);",
        "results.find((r) => r.id === it);",       # Array.find, not a DB call
        "list.filter((r) => r.ok);",
        "fetch(`/api/${it}`);",                    # not awaited: fire-and-forget/concurrent
        "http.get(key);",                          # no URL evidence
    ],
)
def test_ignores_lookalikes_in_loop(tmp_path: Path, stmt: str) -> None:
    assert _scan(tmp_path, _loop(stmt)) == [], stmt


@pytest.mark.parametrize(
    "header",
    ["for (let i = 0; i < n; i++)", "while (queue.length)", "for (const k in obj)"],
)
def test_all_loop_forms_are_recognised(tmp_path: Path, header: str) -> None:
    assert len(_scan(tmp_path, _loop("await db.query('q');", header))) == 1


def test_do_while_is_a_loop(tmp_path: Path) -> None:
    body = "async function f() {\n  do {\n    await db.query('q');\n  } while (more());\n}\n"
    assert len(_scan(tmp_path, body)) == 1


def test_db_call_in_iteration_callback_is_flagged_but_network_is_not(tmp_path: Path) -> None:
    db = "async function f(ids) { await Promise.all(ids.map(async (id) => User.findById(id))); }\n"
    assert len(_scan(tmp_path, db)) == 1
    (tmp_path / "m.js").unlink()
    net = "async function f(ids) { await Promise.all(ids.map(async (id) => await fetch(`/a/${id}`))); }\n"
    assert _scan(tmp_path, net) == []


def test_only_first_round_trip_per_loop_is_reported(tmp_path: Path) -> None:
    body = _loop("await db.query('a');\n    await User.findById(it);")
    assert len(_scan(tmp_path, body)) == 1


def test_call_outside_loop_and_nested_function_scope(tmp_path: Path) -> None:
    body = (
        "async function f(ids) {\n"
        "  await db.query('a');\n"
        "  for (const id of ids) {\n"
        "    const later = async () => db.query('b');\n"
        "    later.id = id;\n"
        "  }\n"
        "}\n"
    )
    assert _scan(tmp_path, body) == []


# ------------------------------------------------------------------ OPT002 / OPT003 / OPT004
def test_string_concat_in_loop_only_for_string_vars(tmp_path: Path) -> None:
    body = (
        "function f(rows) {\n  let s = '';\n  let n = 0;\n"
        "  for (const r of rows) { s += r; n += r; }\n  return s + n;\n}\n"
    )
    findings = _scan(tmp_path, body)
    assert [f.issue_type for f in findings] == ["String concatenation in loop"]


def test_template_string_initialiser_counts_as_string(tmp_path: Path) -> None:
    body = "function f(rows) {\n  let s = ``;\n  for (const r of rows) { s += r; }\n}\n"
    assert len(_scan(tmp_path, body)) == 1


def test_nested_foreach_over_same_collection(tmp_path: Path) -> None:
    body = "function f(items) {\n  items.forEach((a) => { items.forEach((b) => { use(a, b); }); });\n}\n"
    findings = _scan(tmp_path, body)
    assert [f.issue_type.split(" (")[0] for f in findings] == ["Nested loop over same collection"]


def test_nested_loops_over_different_collections_are_fine(tmp_path: Path) -> None:
    body = "function f(xs, ys) {\n  for (const x of xs) { for (const y of ys) { use(x, y); } }\n}\n"
    assert _scan(tmp_path, body) == []


def test_member_chain_collection_key(tmp_path: Path) -> None:
    body = "function f(o) {\n  for (const a of o.items) { for (const b of o.items) { use(a, b); } }\n}\n"
    assert len(_scan(tmp_path, body)) == 1


def test_regexp_literal_pattern_in_loop_only(tmp_path: Path) -> None:
    body = (
        "function f(lines, p) {\n"
        "  for (const l of lines) { new RegExp('a+b').test(l); new RegExp(p).test(l); }\n}\n"
    )
    findings = _scan(tmp_path, body)
    assert len(findings) == 1 and findings[0].issue_type == "Regex pattern re-resolved in loop"


# ------------------------------------------------------------------ languages / robustness
def test_typescript_and_tsx_are_analyzed(tmp_path: Path) -> None:
    ts = "async function f(ids: number[]): Promise<void> {\n  for (const id of ids) {\n    await db.query('q', [id]);\n  }\n}\n"
    assert len(_scan(tmp_path, ts, "svc.ts")) == 1
    tsx = (
        "export function C({ ids }: { ids: number[] }) {\n"
        "  let s = '';\n  for (const id of ids) { s += id; }\n"
        "  return <div>{s}</div>;\n}\n"
    )
    (tmp_path / "svc.ts").unlink()
    findings = _scan(tmp_path, tsx, "c.tsx")
    assert [f.issue_type for f in findings] == ["String concatenation in loop"]


def test_minified_declaration_and_excluded_files_are_skipped(tmp_path: Path) -> None:
    body = _loop("await db.query('q');")
    (tmp_path / "a.min.js").write_text(body, encoding="utf-8")
    (tmp_path / "a.d.ts").write_text(body, encoding="utf-8")
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "dep.js").write_text(body, encoding="utf-8")
    ext = tmp_path / "vendor"
    ext.mkdir()
    (ext / "x.js").write_text(body, encoding="utf-8")
    assert run_optimizer(tmp_path, exclude_dirs={"vendor"}) == []


def test_broken_and_oversized_files_do_not_crash(tmp_path: Path, monkeypatch) -> None:
    assert _scan(tmp_path, "for (const x of ) {{{ await db.query(") is not None
    big = tmp_path / "big.js"
    big.write_text("// " + "x" * 50, encoding="utf-8")
    monkeypatch.setattr(optimization_js, "_MAX_FILE_BYTES", 10)
    assert optimization_js.analyze_js_file(big) == []


def test_missing_grammar_degrades_to_empty(tmp_path: Path, monkeypatch) -> None:
    f = tmp_path / "a.js"
    f.write_text(_loop("await db.query('q');"), encoding="utf-8")
    monkeypatch.setitem(optimization_js._language_cache, "tree_sitter_javascript.language", None)
    assert optimization_js.analyze_js_file(f) == []
    assert optimization_js.analyze_js_file(tmp_path / "x.txt") == []
