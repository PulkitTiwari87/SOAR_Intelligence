"""Process start-up: apply migrations, load the playbook library, create the first admin."""
from __future__ import annotations

import logging
import re

from alembic import command
from alembic.config import Config
from sqlalchemy import func, select

from soar import audit, security
from soar.config import ROOT, get_settings
from soar.db import get_engine, session_scope
from soar.domain import Role
from soar.models import User

log = logging.getLogger("soar.bootstrap")


def run_migrations() -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    with get_engine().begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")


def bootstrap_admin() -> None:
    """Create the first ADMIN from SOAR_ADMIN_USERNAME/SOAR_ADMIN_PASSWORD when no users exist."""
    s = get_settings()
    with session_scope() as db:
        if db.scalar(select(func.count()).select_from(User)):
            return
        if not (s.admin_username and s.admin_password):
            log.warning("No users exist. Set SOAR_ADMIN_USERNAME and SOAR_ADMIN_PASSWORD, or run "
                        "`python -m soar.cli create-user` to create the first admin.")
            return
        if not re.match(r"^[A-Za-z0-9_.-]{3,64}$", s.admin_username):
            log.error("SOAR_ADMIN_USERNAME is invalid; admin not created")
            return
        try:
            pw_hash = security.hash_password(s.admin_password)
        except ValueError as e:
            log.error("SOAR_ADMIN_PASSWORD rejected: %s", e)
            return
        db.add(User(username=s.admin_username, password_hash=pw_hash, role=Role.ADMIN.value))
        audit.record(db, actor="system", action="bootstrap_admin", target_type="user",
                     target_id=s.admin_username)
        log.info("Created initial admin user %s", s.admin_username)


def startup() -> None:
    """Called once from the FastAPI lifespan."""
    s = get_settings()
    s.data_dir.mkdir(parents=True, exist_ok=True)
    if s.env != "testing":  # tests build the schema directly and control their own users
        run_migrations()
        bootstrap_admin()
    from soar.playbooks.library import load_library  # local import: avoids a cycle at import time
    with session_scope() as db:
        load_library(db)
