#!/bin/bash

celery -A rematch.celery worker -l info
