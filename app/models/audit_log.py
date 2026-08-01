"""
models/audit_log.py

SQLAlchemy ORM model for the audit_log table, so Alembic can detect
and migrate it alongside the other models/*.py files.

ASSUMPTION: models/ was empty at the time this file was written, so
the Base import below and naming convention are a best guess at what
the team will standardize on. Update the import to match whatever
Base/declarative setup lands in database.py or models/__init__.py —
this file's column definitions are correct regardless of that choice.

Note: repositories/audit.py queries this table with raw SQL via
SQLAlchemy Core (text()), not through this ORM model directly. This
model exists for Alembic's autogenerate support only. That split —
ORM models for schema/migrations, raw SQL Core for application
queries — is intentional and matches how the rest of the identity
and observation tables are handled in repositories/.
"""

from sqlalchemy import (
    BigInteger, Column, ForeignKey, Integer, String, DateTime, func
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from database import Base  # adjust to match the team's actual Base import


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(BigInteger, primary_key=True)
    organization_id = Column(
        Integer, ForeignKey("organization.id", ondelete="RESTRICT"), nullable=False
    )
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action = Column(String(60), nullable=False)
    entity_type = Column(String(30), nullable=False)
    entity_id = Column(Integer, nullable=True)
    before_value = Column(JSONB, nullable=True)
    after_value = Column(JSONB, nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())

    organization = relationship("Organization")
    user = relationship("User")

    # Deliberately no __table_args__ update/delete hooks here — the
    # immutability guarantee lives in the database trigger
    # (fn_prevent_audit_log_mutation), not in the ORM layer. Relying on
    # the DB means even a direct psql session or a bug in application
    # code cannot bypass it.
