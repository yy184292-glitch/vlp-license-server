from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Boolean, Date, Text, Integer, DateTime, Index
from datetime import datetime, date

class Base(DeclarativeBase):
    pass

class License(Base):
    __tablename__ = "licenses"
    license_key: Mapped[str] = mapped_column(String(64), primary_key=True)
    plan: Mapped[str] = mapped_column(String(32), default="PRO")
    expires_on: Mapped[date] = mapped_column(Date)
    features_json: Mapped[str] = mapped_column(Text, default='{"main":true}')
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    customer_name: Mapped[str] = mapped_column(String(128), default="")
    phone: Mapped[str] = mapped_column(String(64), default="")
    memo: Mapped[str] = mapped_column(Text, default="")

class Machine(Base):
    __tablename__ = "machines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    license_key: Mapped[str] = mapped_column(String(64), index=True)
    machine_id: Mapped[str] = mapped_column(String(128), index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_banned: Mapped[bool] = mapped_column(Boolean, default=False)

Index("ix_machine_license_machine", Machine.license_key, Machine.machine_id, unique=True)

class Nonce(Base):
    __tablename__ = "nonces"
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    used_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Log(Base):
    __tablename__ = "logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor: Mapped[str] = mapped_column(String(16), default="")
    action: Mapped[str] = mapped_column(String(32), default="")
    license_key: Mapped[str] = mapped_column(String(64), default="")
    machine_id: Mapped[str] = mapped_column(String(128), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    result: Mapped[str] = mapped_column(String(16), default="ok")
    reason: Mapped[str] = mapped_column(Text, default="")
    meta_json: Mapped[str] = mapped_column(Text, default="{}")
