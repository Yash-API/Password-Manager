#!/bin/bash

echo "Waiting for database to be ready..."
while ! pg_isready -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME 2>/dev/null; do
    sleep 2
    echo "Still waiting for database..."
done

echo "Database is ready! Starting application..."
exec uvicorn main:app --host 0.0.0.0 --port 8081 
