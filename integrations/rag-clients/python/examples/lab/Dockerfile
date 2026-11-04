# LAB ISOLATION ONLY: runs the reference remote RAG in its own network
# namespace so certification can probe it like a separate host. The product
# itself needs no Docker on the RAG server (see ../../README.md).
FROM python:3.12-slim
RUN pip install --no-cache-dir "langchain-core==1.7.4" "llama-index-core==0.14.25"
RUN useradd --system --home /nonexistent rag
WORKDIR /srv
COPY accessproof_rag /srv/accessproof_rag
COPY examples/remote_rag_server.py /srv/examples/remote_rag_server.py
USER rag
ENTRYPOINT ["python", "/srv/examples/remote_rag_server.py"]
