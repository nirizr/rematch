#!/bin/bash

/rematch_server/start_web.sh 0.0.0.0:8000 &
cd /rematch_server && /rematch_server/start_celery.sh 
