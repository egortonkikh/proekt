"""Периодический импорт логов по расписанию из config.json."""

from __future__ import annotations

import logging
import time

from database import db_session, init_db, load_config
from log_parser import import_logs

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("parser_cron")


def run_once() -> None:
    with db_session() as conn:
        result = import_logs(conn)
    logger.info(
        "Импорт завершён: job=%s imported=%s skipped=%s — %s",
        result["job_id"],
        result["imported"],
        result["skipped"],
        result["message"],
    )


def main() -> None:
    cfg = load_config()
    cron = cfg.get("cron", {})
    if not cron.get("enabled", True):
        logger.info("cron.enabled = false, выход")
        return

    interval = max(1, int(cron.get("interval_minutes", 60)))
    init_db()
    logger.info("Старт cron-импорта, интервал %s мин", interval)

    while True:
        try:
            run_once()
        except Exception:
            logger.exception("Ошибка импорта")
        time.sleep(interval * 60)


if __name__ == "__main__":
    main()
