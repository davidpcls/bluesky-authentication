from pathlib import Path

_here = Path(__file__).resolve().parent
ALEMBIC_INI_TEMPLATE_PATH = str(_here / "alembic.ini.template")
ALEMBIC_DIR = str(_here / "migrations")
