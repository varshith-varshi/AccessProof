FROM python:3.13-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 accessproof
COPY pyproject.toml /app/
COPY apps/demo_ai /app/apps/demo_ai
RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx "PyJWT[crypto]"
USER 10001:10001
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8100
CMD ["uvicorn", "apps.demo_ai.app:app", "--host", "0.0.0.0", "--port", "8100"]
