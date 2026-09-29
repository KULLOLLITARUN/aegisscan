"""Statement-aware SQL chunker."""
from __future__ import annotations

from pathlib import Path

from scanner.chunking import dispatcher
from scanner.chunking.dispatcher import chunk_file, get_chunker
from scanner.chunking.sql_chunker import MAX_CHUNK_LINES, SqlChunker, split_statements
from scanner.ingestion.classifier import FileClassifier


def _chunks(tmp_path: Path, sql: str, name: str = "q.sql"):
    p = tmp_path / name
    p.write_bytes(sql.encode("utf-8"))
    return SqlChunker().chunk(FileClassifier().classify(p))


def _stmts(sql: str) -> list[str]:
    return [sql[s.start:s.end] for s in split_statements(sql)]


# ------------------------------------------------------------------ splitting
def test_splits_on_semicolons_and_keeps_terminator() -> None:
    assert _stmts("SELECT 1;\nSELECT 2;\n") == ["SELECT 1;", "SELECT 2;"]


def test_last_statement_without_terminator_is_kept() -> None:
    assert _stmts("SELECT 1;\nSELECT 2") == ["SELECT 1;", "SELECT 2"]


def test_non_ascii_identifier_does_not_crash_and_is_not_read_as_keyword() -> None:
    # Regression: str.isalpha() is Unicode-aware but the keyword regex is ASCII-only, so a
    # bare non-ASCII letter used to raise AttributeError (found by mypy).
    assert _stmts("SELECT 1;\nSELECT é FROM t;\n") == ["SELECT 1;", "SELECT é FROM t;"]
    # the tail of a non-ASCII identifier must not open a routine block ("éBEGIN" != BEGIN)
    sql = "CREATE TABLE t (éBEGIN int);\nSELECT 2;\n"
    assert _stmts(sql) == ["CREATE TABLE t (éBEGIN int);", "SELECT 2;"]


def test_semicolons_inside_strings_identifiers_and_comments_do_not_split() -> None:
    sql = (
        "INSERT INTO t VALUES ('a;b', 'it''s; fine');\n"
        'SELECT "odd;name" FROM t;\n'
        "SELECT 1; -- trailing; comment\n"
        "/* block; comment /* nested; */ still; comment */ SELECT 2;\n"
    )
    assert len(_stmts(sql)) == 4


def test_dollar_quoted_function_body_is_one_routine_chunk(tmp_path: Path) -> None:
    sql = (
        "CREATE TABLE a (id int);\n"
        "CREATE OR REPLACE FUNCTION bump() RETURNS void AS $fn$\n"
        "BEGIN\n  UPDATE a SET id = id + 1;\n  DELETE FROM a WHERE id > 9;\nEND;\n"
        "$fn$ LANGUAGE plpgsql;\n"
        "SELECT 1;\n"
    )
    chunks = _chunks(tmp_path, sql)
    assert [c.symbol_name for c in chunks] == ["CREATE TABLE a", "CREATE FUNCTION bump", "SELECT"]
    fn = chunks[1]
    assert fn.symbol_type == "function"
    assert "DELETE FROM a" in fn.code and fn.code.rstrip().endswith("plpgsql;")


def test_positional_params_are_not_dollar_quotes() -> None:
    assert len(_stmts("SELECT $1, $2;\nSELECT $1;")) == 2


def test_mysql_delimiter_procedure_is_one_chunk_without_directive(tmp_path: Path) -> None:
    sql = (
        "DELIMITER //\n"
        "CREATE PROCEDURE p()\nBEGIN\n  SELECT 1;\n  SELECT 2;\nEND//\n"
        "DELIMITER ;\n"
        "SELECT 3;\n"
    )
    chunks = _chunks(tmp_path, sql)
    assert [c.symbol_name for c in chunks] == ["CREATE PROCEDURE p", "SELECT"]
    assert "DELIMITER" not in chunks[0].code and "//" not in chunks[0].code
    assert "SELECT 2;" in chunks[0].code and chunks[0].code.rstrip().endswith("END")


def test_begin_end_without_delimiter_keeps_routine_together() -> None:
    sql = (
        "CREATE PROCEDURE p AS\nBEGIN\n  IF 1 = 1 BEGIN\n    SELECT 1;\n  END\n"
        "  SELECT CASE WHEN 1 = 1 THEN 'a;' ELSE 'b' END;\nEND;\n"
        "SELECT 2;\n"
    )
    stmts = _stmts(sql)
    assert len(stmts) == 2 and stmts[0].startswith("CREATE PROCEDURE") and stmts[1] == "SELECT 2;"


def test_begin_transaction_does_not_open_a_block() -> None:
    sql = "BEGIN TRANSACTION;\nUPDATE t SET a = 1;\nCOMMIT;\nBEGIN;\nSELECT 1;\nEND;\n"
    assert len(_stmts(sql)) == 6


def test_end_if_and_end_loop_do_not_close_blocks() -> None:
    sql = (
        "CREATE PROCEDURE p()\nBEGIN\n  IF a THEN SELECT 1; END IF;\n"
        "  WHILE b DO SELECT 2; END WHILE;\nEND;\nSELECT 9;\n"
    )
    stmts = _stmts(sql)
    assert len(stmts) == 2 and stmts[1] == "SELECT 9;"


def test_go_batch_separator() -> None:
    sql = "SELECT 1\nGO\nSELECT 2\ngo 2\nSELECT 3\n"
    assert _stmts(sql) == ["SELECT 1", "SELECT 2", "SELECT 3"]


def test_go_inside_string_or_identifier_is_not_a_separator() -> None:
    assert len(_stmts("SELECT 'a\nGO\nb';\n")) == 1
    assert len(_stmts("SELECT go FROM t;\n")) == 1


def test_backslash_escapes_only_for_mysql_like_or_E_strings() -> None:
    mysql = "INSERT INTO `t` VALUES ('it\\'s; fine');\nSELECT 1;\n"
    assert len(_stmts(mysql)) == 2
    pg_e = "SELECT E'it\\'s; fine';\nSELECT 1;\n"
    assert len(_stmts(pg_e)) == 2
    pg_plain = "SELECT 'C:\\';\nSELECT 1;\n"          # backslash is literal in standard SQL
    assert len(_stmts(pg_plain)) == 2


def test_unterminated_string_and_comment_do_not_crash() -> None:
    assert len(_stmts("SELECT 'oops;\nSELECT 2;")) == 1
    # SELECT 1 is complete; the unterminated comment swallows the rest as one trailing piece
    assert _stmts("SELECT 1; /* never closed; SELECT 2;") == ["SELECT 1;", "/* never closed; SELECT 2;"]


def test_empty_and_comment_only_files() -> None:
    assert split_statements("") == []
    assert split_statements("  \n\n") == []
    assert len(_stmts("-- just a comment\n")) == 1


# ------------------------------------------------------------------ chunk objects
def test_line_numbers_and_leading_comment_belong_to_statement(tmp_path: Path) -> None:
    sql = "-- create users\nCREATE TABLE users (id int);\n\n\nINSERT INTO users VALUES (1);\n"
    c = _chunks(tmp_path, sql)
    assert len(c) == 1  # both small statements pack together
    assert (c[0].line_start, c[0].line_end) == (1, 5)
    assert c[0].symbol_name == "CREATE TABLE users (+1 statements)"
    assert c[0].symbol_type == "module" and c[0].language == "SQL"
    assert c[0].code.startswith("-- create users")


def test_routines_are_never_merged_with_neighbours(tmp_path: Path) -> None:
    sql = (
        "SELECT 1;\nCREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql;\nSELECT 2;\n"
    )
    assert [c.symbol_type for c in _chunks(tmp_path, sql)] == ["module", "function", "module"]


def test_small_statements_are_packed_within_line_limit(tmp_path: Path) -> None:
    sql = "".join(f"INSERT INTO t VALUES ({i});\n" for i in range(200))
    chunks = _chunks(tmp_path, sql)
    assert 3 <= len(chunks) <= 6
    assert all(c.line_end - c.line_start + 1 <= MAX_CHUNK_LINES for c in chunks)
    assert chunks[0].line_start == 1 and chunks[-1].line_end == 200
    # contiguous and lossless: every insert appears exactly once
    joined = "".join(c.code for c in chunks)
    assert joined.count("INSERT INTO t VALUES") == 200


def test_oversized_single_statement_is_not_cut(tmp_path: Path) -> None:
    cols = ",\n".join(f"  c{i} int" for i in range(120))
    sql = f"CREATE TABLE wide (\n{cols}\n);\nSELECT 1;\n"
    chunks = _chunks(tmp_path, sql)
    assert len(chunks) == 2
    assert chunks[0].line_end - chunks[0].line_start + 1 > MAX_CHUNK_LINES
    assert "c119 int" in chunks[0].code


def test_crlf_files_chunk_correctly(tmp_path: Path) -> None:
    c = _chunks(tmp_path, "SELECT 1;\r\nSELECT 2;\r\n")
    assert len(c) == 1 and (c[0].line_start, c[0].line_end) == (1, 2)


def test_statement_naming(tmp_path: Path) -> None:
    sql = "UPDATE users SET a = 1;\n"
    assert _chunks(tmp_path, sql)[0].symbol_name == "UPDATE users"
    (tmp_path / "q.sql").unlink()
    assert _chunks(tmp_path, "DROP TABLE users;\n")[0].symbol_name == "DROP TABLE users"
    (tmp_path / "q.sql").unlink()
    assert _chunks(tmp_path, "CREATE UNIQUE INDEX IF NOT EXISTS ix ON t(a);\n")[0].symbol_name == "CREATE INDEX ix"


def test_unreadable_or_binary_returns_empty(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "q.sql"
    p.write_text("SELECT 1;", encoding="utf-8")
    info = FileClassifier().classify(p)
    monkeypatch.setattr(
        "scanner.chunking.sql_chunker.split_statements", lambda _t: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert SqlChunker().chunk(info) == []


# ------------------------------------------------------------------ dispatcher
def test_dispatcher_routes_sql_to_sql_chunker(tmp_path: Path) -> None:
    p = tmp_path / "s.sql"
    p.write_text("SELECT 1;\n", encoding="utf-8")
    info = FileClassifier().classify(p)
    assert info.language == "SQL"
    assert isinstance(get_chunker(info), SqlChunker)
    assert chunk_file(info)[0].symbol_name == "SELECT"


def test_dispatcher_falls_back_to_generic_when_sql_chunker_returns_nothing(tmp_path: Path, monkeypatch) -> None:
    p = tmp_path / "s.sql"
    p.write_text("SELECT 1;\n", encoding="utf-8")
    info = FileClassifier().classify(p)
    monkeypatch.setattr(dispatcher._sql_chunker, "chunk", lambda _fi: [])
    chunks = chunk_file(info)
    assert len(chunks) == 1 and chunks[0].symbol_type == "module" and chunks[0].symbol_name is None
