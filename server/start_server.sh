#!/bin/bash

if [ -n "$IN_DOCKER" ]; then
  #/rematch_server/create_superuser.py 
  #/rematch_server/start_web.sh 0.0.0.0:8000 &
  cd /rematch_server && /rematch_server/start_celery.sh &
  ./create_superuser.sh
  rm /etc/nginx/sites-enabled/default
  python /rematch_server/manage.py collectstatic --noinput
  ln -sf /rematch_server/rematch_nginx.conf /etc/nginx/sites-enabled/default
  service nginx start
  uwsgi --socket :8001 --module rematch.wsgi
else
  ./start_web.sh 0.0.0.0:8000 &
  ./start_celery.sh
fi
