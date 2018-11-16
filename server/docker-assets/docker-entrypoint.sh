#!/bin/bash

echo "Waiting for database to start..."
while ! pg_isready --host $POSTGRES_HOST --port $POSTGRES_PORT --timeout 10 ; do sleep 2; done

echo "Migrating"
python manage.py migrate

python manage.py collectstatic --settings rematch.settings.docker --noinput

python -c "import django; django.setup();
from django.contrib.auth import get_user_model;
user_model = get_user_model()
try:
    user = user_model.objects.get(username='${REMATCH_SU_NAME}')
    user.email = '${REMATCH_SU_EMAIL}'
    user.set_password('${REMATCH_SU_PASSWORD}')
    user.save()
except user_model.DoesNotExist:
    user_model.objects.create_superuser(
        username='${REMATCH_SU_NAME}',
        email='${REMATCH_SU_EMAIL}',
        password='${REMATCH_SU_PASSWORD}')"

celery -A rematch.celery worker -l info --detach --logfile /var/log/rematch/celery.log
uwsgi --socket :8001 --module rematch.wsgi --env DJANGO_SETTINGS_MODULE=rematch.settings.docker --daemonize /var/log/rematch/uwsgi.log --master
nginx -c docker-assets/nginx.conf

# TODO: include health check for all three services, run all three as daemons
