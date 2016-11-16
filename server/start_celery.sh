#!/bin/sh

celery -A rematch.celery worker -l info
