from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Boolean, Date, Text, Integer, DateTime
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

class Machine(Base):
    __tablename__ = "machines"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    license_key: Mapped[str] = mapped_column(String(64))
    machine_id: Mapped[str] = mapped_column(String(128))

class Nonce(Base):
    __tablename__ = "nonces"
    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    used_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Log(Base):
    __tablename__ = "logs"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
