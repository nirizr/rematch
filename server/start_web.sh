#!/bin/bash

webserver_addr=$1

python /rematch_server/manage.py makemigrations collab
python /rematch_server/manage.py migrate
has_admin=$(echo "select count(*) from auth_user where username='admin';" | python /rematch_server/manage.py dbshell | sed 's/[^0-9]//g')
if [ $has_admin -eq 0 ]; then
    echo "Creating admin super user, please enter password"
    python /rematch_server/manage.py createsuperuser --username admin --email admin@local.com
fi
python /rematch_server/manage.py runserver -v 3 $webserver_addr

