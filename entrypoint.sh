#!/bin/bash

set -e

# Function to check if database is ready with retry
check_db_connection() {
    local retries=30
    local wait_time=5
    local count=0
    echo "Checking connection to database at $DB_HOST:$DB_PORT..."
    
    while [ $count -lt $retries ]; do
        if PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" >/dev/null 2>&1; then
            echo "Successfully connected to the database as user '$DB_USER'!"
            return 0
        fi
        
        echo "Connection attempt $((count+1))/$retries failed. Waiting ${wait_time}s before retry..."
        count=$((count+1))
        
        # After several attempts, print more diagnostic information
        if [ $count -eq 10 ]; then
            echo "Connection troubleshooting info:"
            echo "DB_HOST=$DB_HOST, DB_PORT=$DB_PORT, DB_USER=$DB_USER, DB_NAME=$DB_NAME"
            echo "Testing basic connectivity..."
            nc -zv $DB_HOST $DB_PORT || echo "Cannot reach database host/port!"
        fi
        
        sleep $wait_time
    done
    
    echo "Failed to connect to database after $retries attempts."
    return 1
}

# Function to check for a migration flag
check_migration_flag() {
    # Check if a flag file exists in the database indicating migrations have completed
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1 FROM pg_tables WHERE tablename = 'django_migrations_complete';" | grep -q "1"
    return $?
}

# Function to create migration flag
create_migration_flag() {
    echo "Creating migration complete flag..."
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "CREATE TABLE IF NOT EXISTS django_migrations_complete (id SERIAL PRIMARY KEY, completed_at TIMESTAMP DEFAULT NOW());"
    PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "INSERT INTO django_migrations_complete (completed_at) VALUES (NOW());"
}

# Wait for the database to be ready
echo "Waiting for database..."
while ! nc -z $DB_HOST $DB_PORT; do
  sleep 1
done
echo "Database is reachable!"

# Now test actual database connection
if ! check_db_connection; then
    echo "Could not establish database connection. Exiting."
    exit 1
fi

# Check if this is the init container that only runs migrations
if [ "$RUN_MIGRATIONS_ONLY" = "true" ]; then
    echo "Running as migration-only container"
    
    # Set database connection details for migrations
    export DB_HOST=$DB_HOST
    export DB_PORT=$DB_PORT
    
    # Show migration plan first - this will verify we can access the database
    echo "Migration plan:"
    python manage.py showmigrations
    
    # Run Django migrations with verbose output
    python manage.py migrate --noinput --verbosity 2 || {
        echo "Migrations failed. Checking database connection..."
        PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" || echo "Database connection error!"
        exit 1
    }
    
    echo "Migrations complete."
    
    # Create flag to indicate migrations are complete
    create_migration_flag
    
    # Exit successfully - this container's job is done
    echo "Migration container completed successfully!"
    exit 0
fi

# For regular containers, check if we should skip migrations
if [ "$SKIP_MIGRATIONS" = "true" ]; then
    echo "Skipping migrations as configured."
    
    # Wait for migrations to be completed by the init container
    echo "Waiting for migrations to be completed by init container..."
    ATTEMPT=0
    MAX_ATTEMPTS=60
    
    until check_migration_flag; do
        ATTEMPT=$((ATTEMPT+1))
        if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
            echo "Migration flag not found after $MAX_ATTEMPTS attempts. Continuing anyway..."
            break
        fi
        echo "Waiting for migrations to complete (attempt $ATTEMPT/$MAX_ATTEMPTS)..."
        sleep 5
    done
    
    echo "Migrations have been completed by init container."
else
    # This is a fallback for backward compatibility
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
        
        # Show migration plan first - this will verify we can access the database
        echo "Migration plan:"
        python manage.py showmigrations
        
        # Run Django migrations with verbose output
        python manage.py migrate --noinput --verbosity 2 || {
            echo "Migrations failed. Checking database connection..."
            PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "SELECT 1;" || echo "Database connection error!"
            exit 1
        }
        
        echo "Migrations complete."
        
        # Create migration complete flag
        create_migration_flag
        
        # Delete our lock
        PGPASSWORD=$DB_PASSWORD psql -h $DB_HOST -U $DB_USER -d $DB_NAME -c "DELETE FROM django_migration_lock WHERE instance_id = '$INSTANCE_ID';" 2>/dev/null
    else
        echo "Another instance is handling migrations. Waiting for completion..."
        # Wait for migrations to complete
        ATTEMPT=0
        MAX_ATTEMPTS=60
        
        until check_migration_flag; do
            ATTEMPT=$((ATTEMPT+1))
            if [ $ATTEMPT -ge $MAX_ATTEMPTS ]; then
                echo "Migration flag not found after $MAX_ATTEMPTS attempts. Continuing anyway..."
                break
            fi
            echo "Waiting for migrations to complete (attempt $ATTEMPT/$MAX_ATTEMPTS)..."
            sleep 5
        done
    fi
fi

# Once migrations are done, update DB settings to use PgBouncer if configured
if [ -n "$PGBOUNCER_HOST" ] && [ -n "$PGBOUNCER_PORT" ]; then
    echo "Switching database connection to PgBouncer at $PGBOUNCER_HOST:$PGBOUNCER_PORT"
    export DB_HOST=$PGBOUNCER_HOST
    export DB_PORT=$PGBOUNCER_PORT
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