import os
from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, String, DateTime, Integer, func
from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    async_sessionmaker,
    create_async_engine,
    AsyncSession,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Defaults to a local sqlite file for running the app outside a container.
# In Kubernetes this is overridden by a DATABASE_URL env var pointing at
# Postgres, e.g. postgresql+asyncpg://user:pass@host:5432/drydock
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./drydock.db")

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(AsyncAttrs, DeclarativeBase):
    pass


class SBOMSubmission(Base):
    __tablename__ = "sbom_submissions"

    id: Mapped[int] = mapped_column(primary_key=True)
    filename: Mapped[str] = mapped_column(String(255))
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    package_count: Mapped[int] = mapped_column(Integer, default=0)
    scan_status: Mapped[str] = mapped_column(String(20), default="pending")
    last_scanned_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    packages: Mapped[list["Package"]] = relationship(
        back_populates="submission", cascade="all, delete-orphan"
    )


class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True)
    submission_id: Mapped[int] = mapped_column(ForeignKey("sbom_submissions.id"))
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(100))
    # None when the SBOM component's purl doesn't map to a known OSV.dev
    # ecosystem. Such packages are stored but skipped during scanning.
    ecosystem: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    purl: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    submission: Mapped["SBOMSubmission"] = relationship(back_populates="packages")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="package", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    """Local cache of vulnerability details already hydrated from OSV.dev.

    Keyed by the OSV/GHSA id itself so repeat scans (across any submission)
    reuse a cached record instead of re-fetching details we already have.
    """

    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    summary: Mapped[str] = mapped_column(String(2000), default="")
    severity: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"))
    vuln_id: Mapped[str] = mapped_column(ForeignKey("vulnerabilities.id"))
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Set when a later scan no longer reports this vuln for the package.
    # This is the field the Phase 5 time-to-remediate metric comes from.
    resolved_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    package: Mapped["Package"] = relationship(back_populates="findings")


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
