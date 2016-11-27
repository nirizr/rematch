#!/bin/bash

tmux new-session -s rematch -d ./start_web.sh
tmux new-window -t rematch -d ./start_celery.sh
tmux new-window -t rematch
