#!/bin/sh

set -e

echo "Waiting for PostgreSQL..."

while ! python manage.py check --database default >/dev/null 2>&1
do
    sleep 2
done

echo "PostgreSQL is ready."

echo "Running migrations..."
python manage.py migrate --noinput

echo "Seeding default superuser / admin account..."
python create_admin.py

echo "Bootstrapping Learning Center articles and taxonomy..."
python manage.py bootstrap_learning_center || true

echo "Collecting static files..."
python manage.py collectstatic --noinput

echo "Starting Gunicorn..."

exec "$@"