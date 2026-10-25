FROM node:22-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" PYTHON_BIN=/opt/venv/bin/python

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build
# Pre-load the three preset projects. If the build has no network, start.sh retries at boot.
RUN python -m backend.ingest seed || echo "WARN: preset seeding failed at build time"

ENV NODE_ENV=production PORT=8080 GRAPH_BACKEND=sqlite
EXPOSE 8080
CMD ["sh", "start.sh"]
