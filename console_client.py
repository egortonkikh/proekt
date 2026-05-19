"""Консольный клиент: инициализация БД, импорт, статистика."""

from __future__ import annotations

import argparse
import json
import sys

from database import db_path, db_session, get_stats, init_db, load_config
from log_parser import import_logs


def cmd_init(_: argparse.Namespace) -> int:
    path = init_db()
    print(f"OK: база {path}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    init_db()
    with db_session() as conn:
        result = import_logs(conn, full=args.full)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_stats(_: argparse.Namespace) -> int:
    init_db()
    with db_session() as conn:
        stats = get_stats(conn)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Apache log aggregator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Создать project.db и таблицы")
    p_init.set_defaults(func=cmd_init)

    p_import = sub.add_parser("import", help="Импортировать логи из папки logs/")
    p_import.add_argument(
        "--full",
        action="store_true",
        help="Полный переимпорт (очистить данные)",
    )
    p_import.set_defaults(func=cmd_import)

    p_stats = sub.add_parser("stats", help="Показать статистику")
    p_stats.set_defaults(func=cmd_stats)

    args = parser.parse_args()
    cfg = load_config()
    print(f"База: {db_path()}", file=sys.stderr)
    print(f"Логи: {cfg['logs']['directory']}", file=sys.stderr)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
