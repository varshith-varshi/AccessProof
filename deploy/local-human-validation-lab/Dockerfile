FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv/lab
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN useradd -u 1000 -m lab && mkdir -p /data && chown -R lab:lab /data /srv/lab
COPY --chown=lab:lab app /srv/lab/app
USER lab
EXPOSE 8187
CMD ["uvicorn", "app.api:app", "--host", "0.0.0.0", "--port", "8187"]
