# Use an official Python runtime as a base image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE=trading_service_project.settings

# Set work directory
WORKDIR /app

# Install system dependencies (added debugging tools)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        postgresql-client \
        build-essential \
        libpq-dev \
        netcat-openbsd \
        curl \
        strace \
        dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directory for static files and logs
RUN mkdir -p staticfiles logs

# Create a non-root user
RUN adduser --disabled-password --gecos '' appuser

# Fix script permissions and ensure Unix line endings
RUN chmod +x /app/docker-entrypoint.sh && \
    dos2unix /app/docker-entrypoint.sh && \
    echo "Entrypoint script permissions: $(ls -la /app/docker-entrypoint.sh)" && \
    echo "Build timestamp: $(date)" && \
    cat /app/docker-entrypoint.sh | head -n 3

RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8000

# Use the entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"]