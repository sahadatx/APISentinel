from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, inspect, pool

from apisentinel import models  # noqa: F401
from apisentinel.config import settings
from apisentinel.db import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)
config.set_main_option("sqlalchemy.url", settings.database_url.replace("%", "%%"))
target_metadata = Base.metadata


def run_migrations_offline():
    context.configure(url=settings.database_url, target_metadata=target_metadata, literal_binds=True, dialect_opts={"paramstyle": "named"}, compare_type=True)
    with context.begin_transaction(): context.run_migrations()


def run_migrations_online():
    connectable = engine_from_config(config.get_section(config.config_ini_section), prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        # Alembic defaults version_num to VARCHAR(32), but this project's
        # descriptive revision identifiers are longer. Widen/create the table
        # before Alembic attempts to write a new revision on PostgreSQL.
        if connection.dialect.name == "postgresql":
            if inspect(connection).has_table("alembic_version"):
                connection.exec_driver_sql(
                    "ALTER TABLE alembic_version ALTER COLUMN version_num TYPE VARCHAR(128)"
                )
            else:
                connection.exec_driver_sql(
                    "CREATE TABLE alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)"
                )
            # Commit the schema bootstrap before Alembic opens its migration transaction.
            connection.commit()
        context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction(): context.run_migrations()


if context.is_offline_mode(): run_migrations_offline()
else: run_migrations_online()
