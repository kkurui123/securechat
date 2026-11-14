from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings

url = make_url(settings().database_url.get_secret_value())
if url.drivername not in {"postgres", "postgresql", "postgresql+psycopg"}:
    raise ValueError("PostgreSQL required")
url = url.set(drivername="postgresql+psycopg")
if "sslmode" not in url.query:
    url = url.update_query_dict({"sslmode": "require"})
if url.query.get("sslmode") not in {"require", "verify-ca", "verify-full"}:
    raise ValueError("TLS required")
engine = create_engine(url, pool_pre_ping=True, pool_size=3, max_overflow=2,
                       connect_args={"connect_timeout": 10}, hide_parameters=True)
SessionLocal = sessionmaker(engine, expire_on_commit=False)
class Base(DeclarativeBase):
    pass

def get_db():
    with SessionLocal() as db:
        yield db
