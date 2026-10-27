FROM python:3.13-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

RUN addgroup --system accessproof && adduser --system --ingroup accessproof --home /nonexistent accessproof
COPY pyproject.toml /app/
COPY packages /app/packages
COPY apps/guard /app/apps/guard
RUN pip install --no-cache-dir . && mkdir -p /var/lib/accessproof-guard && chown -R accessproof:accessproof /var/lib/accessproof-guard
COPY apps/guard/docker-entrypoint.sh /usr/local/bin/accessproof-guard-entrypoint
RUN chmod 0755 /usr/local/bin/accessproof-guard-entrypoint

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/accessproof-guard-entrypoint"]
CMD ["python", "-m", "uvicorn", "apps.guard.accessproof_guard.app:app", "--host", "0.0.0.0", "--port", "8080"]
