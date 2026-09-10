FROM python:3.12-slim

# Prevents Python from buffering stdout/stderr (nicer logs on Render)
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend_server.py .

# Render sets $PORT at runtime; default to 8000 for local `docker run`
ENV PORT=8000
EXPOSE 8000

# Use sh -c so the $PORT env var expands correctly on Render
CMD ["sh", "-c", "uvicorn backend_server:app --host 0.0.0.0 --port ${PORT}"]
