FROM python:3.13-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 accessproof
COPY pyproject.toml alembic.ini /app/
COPY migrations /app/migrations
COPY packages /app/packages
COPY connectors /app/connectors
COPY integrations /app/integrations
COPY apps/api /app/apps/api
# Generated before deployment by scripts/build-guard-package.sh.
COPY packaging/guard/releases/ /app/guard-releases/
COPY scripts/ensure_current_database.py scripts/check_schema.py /app/scripts/
RUN pip install --no-cache-dir ".[observability]"
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["uvicorn", "apps.api.accessproof_api.app:app", "--host", "0.0.0.0", "--port", "8000"]
