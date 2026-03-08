# Create SQLite DB and JSON fallback with translation templates for x86_64
import sqlite3
from pathlib import Path
from os import getcwd

CWD = Path(getcwd())
OUT_DB = Path(CWD / "translation_tables.db")


def main():
    if OUT_DB.exists():
        OUT_DB.unlink()
    conn = sqlite3.connect(str(OUT_DB))
    cur = conn.cursor()

    with open(CWD / "create_tables.sql") as f:
        cur.executescript(f.read())

    conn.commit()
    conn.commit()
    conn.close()


if __name__ == "__main__":
    main()
