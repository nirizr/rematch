#!/bin/bash

if [[ -n "$IN_DOCKER" ]];
then
  echo "starting celeryin docker mode!"
  while ! nc -z db 3306 ; do sleep 2; done
  celery -A rematch.celery_docker worker -l info
else
  echo "starting celeryin debug mode!"
  celery -A rematch.celery worker -l info
fi
