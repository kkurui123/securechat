import argparse
from sqlalchemy import select
from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.models.entities import User
from app.guards.auth import passwords

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--create-tables", action="store_true", help="Initial empty database only; not migrations")
    args = parser.parse_args()
    if args.create_tables:
        Base.metadata.create_all(engine)
    cfg = settings()
    if not cfg.admin_password or len(cfg.admin_password.get_secret_value()) < 12:
        raise SystemExit("Set ADMIN_PASSWORD to a new password of at least 12 characters")
    with SessionLocal() as db:
        existing = db.scalar(select(User).where(User.email == cfg.admin_email.lower()))
        if existing:
            if existing.role != "ADMIN":
                raise SystemExit("Email belongs to a Guard; refusing privilege escalation")
            print("Admin already exists; password unchanged")
            return
        db.add(User(email=cfg.admin_email.lower(), role="ADMIN", phone=None,
                    password_hash=passwords.hash(cfg.admin_password.get_secret_value())))
        db.commit()
        print("Admin created")

if __name__ == "__main__":
    main()
