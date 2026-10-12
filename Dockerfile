# SecureLens AI - application container
# NOTE: this container runs the Streamlit UI + analyzers. It never executes
# user-uploaded source code; Semgrep/Bandit/AST only *parse* it.
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user; analysis never runs as root
RUN useradd -m -u 1000 securelens
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN mkdir -p /app/uploads /app/reports_output /app/chroma_db \
    && chown -R securelens:securelens /app

USER securelens

# Resource-limited, non-networked-by-default analysis container.
# The compose file additionally drops capabilities and sets read-only FS
# for a dedicated "analyzer sandbox" profile (see docker-compose.yml).
EXPOSE 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
