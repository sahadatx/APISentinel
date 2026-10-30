FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 apisentinel && useradd --system --uid 10001 --gid apisentinel --home-dir /app apisentinel
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY migrations ./migrations
COPY alembic.ini ./
RUN pip install --no-cache-dir . && mkdir -p /data && chown -R apisentinel:apisentinel /app /data
USER 10001:10001
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && apisentinel serve --host 0.0.0.0"]
