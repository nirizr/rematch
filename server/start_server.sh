#!/bin/bash

if [ -n "$IN_DOCKER" ]; then
  #/rematch_server/create_superuser.py 
  /rematch_server/start_web.sh 0.0.0.0:8000 &
  cd /rematch_server && /rematch_server/start_celery.sh &&
   uwsgi --socket :80001 --module rematch.wsgi
else
  ./create_superuser.sh
  ./start_web.py 0.0.0.0:8000 &
  ./start_celery.sh
fi;
