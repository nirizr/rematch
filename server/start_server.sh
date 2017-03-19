#!/bin/bash

if [ -n "$IN_DOCKER" ]; then
  #/rematch_server/create_superuser.py 
  #/rematch_server/start_web.sh 0.0.0.0:8000 &
  cd /rematch_server && /rematch_server/start_celery.sh &&
  sudo service nginx start
  uwsgi --socket :8001 --module rematch.wsgi
else
  ./start_web.sh 0.0.0.0:8000 &
  ./start_celery.sh
fi;
