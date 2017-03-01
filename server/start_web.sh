#!/bin/bash

webserver_addr=$1

python /code/code/manage.py makemigrations collab
python /code/code/manage.py migrate
has_admin=$(echo "select count(*) from auth_user where username='admin';" | python /code/code/manage.py dbshell | sed 's/[^0-9]//g')
if [ $has_admin -eq 0 ]; then
    echo "Creating admin super user, please enter password"
    python /code/code/manage.py createsuperuser --username admin --email admin@local.com
fi
python /code/code/manage.py runserver -v 3 $webserver_addr

celery -A rematch.celery worker -l info
