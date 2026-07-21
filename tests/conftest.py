import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app import db as db_module
from app.db import Base
from app.main import app


@pytest_asyncio.fixture
async def db_session_factory():
    """Fresh in-memory sqlite DB per test, wired in via dependency override.

    StaticPool + check_same_thread=False is required for sqlite ':memory:'
    under async SQLAlchemy: without it, each connection checkout gets its
    own empty in-memory database and tables silently disappear between
    queries.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override_get_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[db_module.get_db] = override_get_db

    # The background scan task doesn't go through Depends(get_db) -- it
    # opens its own session directly via app.db.AsyncSessionLocal. Swap
    # that module attribute too, so background-task DB access lands in
    # the same in-memory test database instead of the real default one.
    original_session_local = db_module.AsyncSessionLocal
    db_module.AsyncSessionLocal = factory

    yield factory

    db_module.AsyncSessionLocal = original_session_local
    app.dependency_overrides.clear()
    await engine.dispose()
