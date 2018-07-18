FROM python:3.6
ENV PYTHONUNBUFFERED 1
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -qy apt-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq \
          python-dev build-essential python-pip python-numpy python-sklearn \
          netcat-traditional rabbitmq-server nginx
RUN DEBIAN_FRONTEND=noninteractive apt-get clean
RUN DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq
RUN useradd --no-log-init -m -d /rematch_server rematch
WORKDIR /rematch_server
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/server/ ./tests/server/
RUN pip install --upgrade pip uwsgi
RUN pip install -r /rematch_server/server/requirements.txt
RUN mkdir /var/log/rematch/ && chown rematch:rematch /var/log/rematch
RUN rm /etc/nginx/sites-enabled/default
RUN ln -sf /rematch_server/server/nginx.conf /etc/nginx/sites-enabled/rematch
USER rematch
RUN python /rematch_server/server/manage.py collectstatic --settings rematch.settings.docker --noinput
USER root
CMD cd /rematch_server/server ; ./start_docker.sh
