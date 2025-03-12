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

# Ensure entrypoint script is executable
RUN chmod +x /app/entrypoint.sh && \
    dos2unix /app/entrypoint.sh && \
    echo "Entrypoint script permissions: $(ls -la /app/entrypoint.sh)" && \
    echo "Build timestamp: $(date)"

RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose the port the app runs on
EXPOSE 8000

# Use our entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]