FROM python:3.13-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN addgroup --system accessproof && adduser --system --ingroup accessproof --home /nonexistent accessproof
COPY pyproject.toml /app/
COPY packages /app/packages
COPY apps/gateway /app/apps/gateway
RUN pip install --no-cache-dir .
USER accessproof
EXPOSE 8090
CMD ["python", "-m", "uvicorn", "apps.gateway.accessproof_gateway.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8090"]
