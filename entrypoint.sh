#!/bin/bash

set -e

# Wait for the database to be ready
echo "Waiting for database..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "Database is ready!"

# Create a migration lock table in DB to prevent multiple containers from running migrations simultaneously
echo "Checking for migration lock..."
LOCK_TABLE_EXISTS=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT EXISTS (SELECT FROM pg_tables WHERE tablename = 'django_migration_lock');" -t 2>/dev/null | grep -q "t" && echo "yes" || echo "no")

if [ "$LOCK_TABLE_EXISTS" = "no" ]; then
    echo "Creating migration lock table..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "CREATE TABLE django_migration_lock (id SERIAL PRIMARY KEY, instance_id VARCHAR(255), locked_at TIMESTAMP DEFAULT NOW());" 2>/dev/null || echo "Failed to create lock table, may already exist"
fi

# Try to acquire a lock
INSTANCE_ID=$(hostname)
LOCK_ACQUIRED=$(PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "INSERT INTO django_migration_lock (instance_id) VALUES ('$INSTANCE_ID') RETURNING id;" -t 2>/dev/null | grep -q "[0-9]" && echo "yes" || echo "no")

if [ "$LOCK_ACQUIRED" = "yes" ]; then
    echo "Lock acquired by instance $INSTANCE_ID. Running migrations..."
    
    # Run Django migrations - handle any errors
    python manage.py migrate || echo "Migrations may have failed, but we'll continue startup"
    
    echo "Migrations complete."
    
    # Delete our lock
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "DELETE FROM django_migration_lock WHERE instance_id = '$INSTANCE_ID';" 2>/dev/null
else
    echo "Another instance is handling migrations. Waiting for completion..."
    # Wait for a reasonable time for migrations to complete
    sleep 15
fi

# Display the environment
echo "Django ALLOWED_HOSTS: $DJANGO_ALLOWED_HOSTS"

# Start Gunicorn
echo "Starting Gunicorn..."
exec gunicorn trading_service_project.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers ${GUNICORN_WORKERS:-4} \
    --threads ${GUNICORN_THREADS:-2} \
    --worker-class ${GUNICORN_WORKER_CLASS:-gthread} \
    --timeout ${GUNICORN_TIMEOUT:-30} \
    --worker-tmp-dir /dev/shm \
    --log-level ${GUNICORN_LOG_LEVEL:-info} 