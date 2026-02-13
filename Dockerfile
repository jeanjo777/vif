# Vif - Python/Flask Chat Application with Playwright
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for Playwright and other tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    # Playwright dependencies
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxkbcommon0 \
    libatspi2.0-0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libcairo2 \
    libx11-6 \
    libx11-xcb1 \
    libxcb1 \
    libxext6 \
    fonts-liberation \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements-prod.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-prod.txt

# Install Playwright browsers (chromium only for smaller image)
ENV PLAYWRIGHT_BROWSERS_PATH=/app/.cache/ms-playwright
RUN playwright install chromium --with-deps || echo "Playwright install skipped"

# Copy application code
COPY . .

# Expose port (Railway will set PORT env var)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8080/health')" || exit 1

# Start Flask server
CMD ["sh", "-c", "gunicorn chat_server:app --bind 0.0.0.0:${PORT:-8080} --workers 4 --timeout 120"]
