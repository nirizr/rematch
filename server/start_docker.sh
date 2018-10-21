#!/bin/bash

echo "Waiting for database to start..."
while ! nc -z $POSTGRES_HOST $POSTGRES_PORT ; do sleep 2; done

if [[ ! -d './rematch/migrations' ]];
then
  echo "first time, migrating"
  python manage.py makemigrations collab
  python manage.py migrate
fi

python manage.py collectstatic --settings rematch.settings.docker --noinput

celery -A rematch.celery worker -l info --detach --logfile /var/log/rematch/celery.log
uwsgi --socket :8001 --module rematch.wsgi --env DJANGO_SETTINGS_MODULE=rematch.settings.docker --daemonize /var/log/rematch/uwsgi.log --master
nginx -c /rematch_server/server/nginx.conf

# TODO: include health check for all three services, run all three as daemons
