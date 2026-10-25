FROM python:3.13-slim

WORKDIR /app

COPY drive-rag-demo/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY packages /app/packages
COPY drive-rag-demo/app.py .

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8200"]
