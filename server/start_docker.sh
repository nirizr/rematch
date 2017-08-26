#!/bin/bash
if [[ ! -d './rematch/migrations' ]];
then
  echo "first time, migrating"
  python manage.py makemigrations collab
  python manage.py migrate
fi

echo "Waiting for database to start..."
while ! nc -z db 3306 ; do sleep 2; done

celery -A rematch.celery_docker worker -l info &
uwsgi --socket :8001 --module rematch.wsgi &
nginx -g 'daemon off;'
