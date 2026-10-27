FROM python:3.13-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 accessproof
COPY pyproject.toml alembic.ini /app/
COPY migrations /app/migrations
COPY packages /app/packages
COPY connectors /app/connectors
COPY integrations /app/integrations
COPY apps/api /app/apps/api
COPY apps/worker /app/apps/worker
RUN pip install --no-cache-dir ".[observability]"
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "apps.worker.accessproof_worker.main"]
