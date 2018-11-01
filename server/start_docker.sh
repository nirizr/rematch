#!/bin/bash

echo "Waiting for database to start..."
while ! nc -z $POSTGRES_HOST $POSTGRES_PORT ; do sleep 2; done

echo "Migrating"
python manage.py makemigrations collab
python manage.py migrate

python manage.py collectstatic --settings rematch.settings.docker --noinput

python -c "import django; django.setup();
from django.contrib.auth import get_user_model;
user_model = get_user_model()
if user_model.objects.filter(username='${REMATCH_SU_NAME}').count():
    user_model.objects.filter(username='${REMATCH_SU_NAME}').update(
        email='${REMATCH_SU_EMAIL}',
        password='${REMATCH_SU_PASSWORD}')
else:
    user_model.objects.create_superuser(
        username='${REMATCH_SU_NAME}',
        email='${REMATCH_SU_EMAIL}',
        password='${REMATCH_SU_PASSWORD}')"

celery -A rematch.celery worker -l info --detach --logfile /var/log/rematch/celery.log
uwsgi --socket :8001 --module rematch.wsgi --env DJANGO_SETTINGS_MODULE=rematch.settings.docker --daemonize /var/log/rematch/uwsgi.log --master
nginx -c /rematch_server/server/nginx.conf

# TODO: include health check for all three services, run all three as daemons
