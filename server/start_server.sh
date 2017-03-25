#!/bin/bash
if [ -n "$IN_DOCKER" ]; then
  ./start_celery.sh &
  uwsgi --socket :8001 --module rematch.wsgi
else
  ./start_web.sh 0.0.0.0:8000 &
  ./start_celery.sh
fi
