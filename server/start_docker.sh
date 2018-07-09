#!/bin/bash

if [[ ! -d './rematch/migrations' ]];
then
  echo "first time, migrating"
  python manage.py makemigrations collab
  python manage.py migrate
fi

echo "Waiting for database to start..."
while ! nc -z db 3306 ; do sleep 2; done

celery -A rematch.celery_docker worker -l info --detach --logfile /var/log/rematch/celery.log --uid=rematch --gid=rematch
uwsgi --uid=rematch --gid=rematch --socket :8001 --module rematch.wsgi --env DJANGO_SETTINGS_MODULE=rematch.settings.docker --daemonize /var/log/rematch/uwsgi.log --master
nginx -g 'daemon off;'

# TODO: include health check for all three services, run all three as daemons
