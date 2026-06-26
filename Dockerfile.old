# ============================================================
# Incident Zero — Multi-stage Dockerfile
#
# Stage 1: Build Next.js frontend (static export)
# Stage 2: Run FastAPI backend + serve frontend static files
#
# Build:  docker build -t incident-zero .
# Run:    docker run -p 8000:8000 --env-file .env incident-zero
# ============================================================

# --- Stage 1: Frontend build ---
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend

# Install deps first (layer caching)
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts

# Copy source and build
COPY frontend/ ./
RUN npm run build


# --- Stage 2: Backend runtime ---
FROM python:3.11-slim AS runtime

# Security: run as non-root
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --create-home appuser

WORKDIR /app

# System deps for Pillow
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libjpeg62-turbo \
        libpng16-16 \
        libtiff6 \
        libwebp7 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Python deps
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ ./backend/
COPY schemas/ ./schemas/
COPY fixtures/ ./fixtures/

# Copy built frontend
COPY --from=frontend-build /app/frontend/.next ./frontend/.next
COPY --from=frontend-build /app/frontend/public ./frontend/public
COPY --from=frontend-build /app/frontend/node_modules ./frontend/node_modules
COPY --from=frontend-build /app/frontend/package.json ./frontend/package.json

# Create upload directory
RUN mkdir -p /app/uploads && chown appuser:appuser /app/uploads

# Environment defaults
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UPLOAD_DIR=/app/uploads \
    CORS_ALLOW_ORIGINS=http://localhost:3000,http://localhost:8000

EXPOSE 8000

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
