#!/bin/bash
./start_web.sh 0.0.0.0:8000 &
./start_celery.sh
