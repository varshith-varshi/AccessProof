FROM python:3.13-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 accessproof
COPY pyproject.toml /app/
COPY packages /app/packages
COPY connectors /app/connectors
COPY apps/runner /app/apps/runner
RUN pip install --no-cache-dir ".[observability]"
RUN mkdir -p /app/.accessproof-runner && chown 10001:10001 /app/.accessproof-runner
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "apps.runner.accessproof_runner.main"]
