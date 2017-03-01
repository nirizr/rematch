#!/bin/bash

/code/code/start_web.sh 0.0.0.0:8000 &
cd /code/code/ && /code/code/start_celery.sh &
