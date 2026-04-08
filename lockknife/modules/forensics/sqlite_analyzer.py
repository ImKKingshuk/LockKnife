from __future__ import annotations

import dataclasses
import pathlib
import sqlite3
from typing import Any


@dataclasses.dataclass(frozen=True)
class ColumnInfo:
    name: str
    declared_type: str | None
    not_null: bool
    default_value: str | None
    primary_key: bool


@dataclasses.dataclass(frozen=True)
class TableInfo:
    name: str
    row_count: int | None
    schema_sql: str | None
    columns: list[ColumnInfo] = dataclasses.field(default_factory=list)
    sample_rows: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    timestamp_columns: list[str] = dataclasses.field(default_factory=list)
    index_names: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass(frozen=True)
class DatabaseObject:
    name: str
    object_type: str
    table_name: str | None
    sql: str | None


@dataclasses.dataclass(frozen=True)
class SqliteAnalysis:
    path: str
    tables: list[TableInfo]
    objects: list[DatabaseObject] = dataclasses.field(default_factory=list)
    pragma: dict[str, Any] = dataclasses.field(default_factory=dict)
    wal: dict[str, Any] = dataclasses.field(default_factory=dict)
    rollback_journal: dict[str, Any] = dataclasses.field(default_factory=dict)
    summary: dict[str, Any] = dataclasses.field(default_factory=dict)
    file_size_bytes: int = 0
    integrity_check: str | None = None


def analyze_sqlite(
    path: pathlib.Path, *, max_tables: int = 200, sample_rows: int = 3
) -> SqliteAnalysis:
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name LIMIT ?",
            (max_tables * 4,),
        ).fetchall()
        objects = [
            DatabaseObject(
                name=str(row[1]),
                object_type=str(row[0]),
                table_name=str(row[2]) if row[2] is not None else None,
                sql=str(row[3]) if row[3] is not None else None,
            )
            for row in rows
            if row[1]
        ]
        tables: list[TableInfo] = []
        for item in objects:
            if item.object_type != "table":
                continue
            columns = _columns_for_table(con, item.name)
            tables.append(
                TableInfo(
                    name=item.name,
                    row_count=_safe_scalar(
                        con, f"SELECT COUNT(*) FROM {_quote_identifier(item.name)}"
                    ),  # nosec B608
                    schema_sql=item.sql,
                    columns=columns,
                    sample_rows=_sample_rows(con, item.name, limit=sample_rows),
                    timestamp_columns=[
                        column.name
                        for column in columns
                        if any(
                            token in column.name.lower()
                            for token in (
                                "time",
                                "date",
                                "created",
                                "updated",
                                "modified",
                                "timestamp",
                                "last_",
                            )
                        )
                    ],
                    index_names=[
                        obj.name
                        for obj in objects
                        if obj.object_type == "index" and obj.table_name == item.name
                    ],
                )
            )
        wal_path = pathlib.Path(str(path) + "-wal")
        journal_path = pathlib.Path(str(path) + "-journal")
        return SqliteAnalysis(
            path=str(path),
            tables=tables,
            objects=objects,
            pragma=_pragma_summary(con),
            wal={
                "path": str(wal_path),
                "exists": wal_path.exists(),
                "size_bytes": wal_path.stat().st_size if wal_path.exists() else 0,
            },
            rollback_journal={
                "path": str(journal_path),
                "exists": journal_path.exists(),
                "size_bytes": journal_path.stat().st_size if journal_path.exists() else 0,
            },
            summary={
                "table_count": len(tables),
                "object_count": len(objects),
                "index_count": sum(1 for obj in objects if obj.object_type == "index"),
                "view_count": sum(1 for obj in objects if obj.object_type == "view"),
                "trigger_count": sum(1 for obj in objects if obj.object_type == "trigger"),
                "tables_with_timestamp_columns": [
                    table.name for table in tables if table.timestamp_columns
                ],
            },
            file_size_bytes=path.stat().st_size,
            integrity_check=_string_scalar(con, "PRAGMA integrity_check"),
        )
    finally:
        con.close()


def _safe_scalar(con: sqlite3.Connection, sql: str) -> int | None:
    try:
        row = con.execute(sql).fetchone()
    except Exception:
        return None
    if row is None:
        return None
    value = row[0]
    return int(value) if isinstance(value, int) else None


def _string_scalar(con: sqlite3.Connection, sql: str) -> str | None:
    try:
        row = con.execute(sql).fetchone()
    except Exception:
        return None
    if row is None or row[0] is None:
        return None
    return str(row[0])


def _quote_identifier(name: str) -> str:
    if "\x00" in name:
        raise ValueError("SQLite identifier contains NUL byte")
    return '"' + name.replace('"', '""') + '"'


def _columns_for_table(con: sqlite3.Connection, table_name: str) -> list[ColumnInfo]:
    try:
        rows = con.execute(f"PRAGMA table_info({_quote_identifier(table_name)})").fetchall()  # nosec B608
    except Exception:
        return []
    return [
        ColumnInfo(
            name=str(row[1]),
            declared_type=str(row[2]) if row[2] is not None else None,
            not_null=bool(row[3]),
            default_value=str(row[4]) if row[4] is not None else None,
            primary_key=bool(row[5]),
        )
        for row in rows
    ]


def _sample_rows(con: sqlite3.Connection, table_name: str, *, limit: int) -> list[dict[str, Any]]:
    try:
        row_limit = max(0, int(limit))
        rows = con.execute(
            f"SELECT * FROM {_quote_identifier(table_name)} LIMIT {row_limit}"
        ).fetchall()  # nosec B608
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for row in rows:
        item: dict[str, Any] = {}
        for key in row.keys():
            value = row[key]
            item[key] = value[:24].hex() if isinstance(value, bytes) else value
        out.append(item)
    return out


def _pragma_summary(con: sqlite3.Connection) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in [
        "page_size",
        "page_count",
        "freelist_count",
        "journal_mode",
        "auto_vacuum",
        "user_version",
        "application_id",
        "schema_version",
        "encoding",
    ]:
        summary[key] = _string_scalar(con, f"PRAGMA {key}")
    return summary
