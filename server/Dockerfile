FROM python:latest
ENV PYTHONUNBUFFERED 1
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -qy apt-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq python-dev \
          python-mysqldb build-essential default-libmysqlclient-dev python-pip \
          python-numpy python-sklearn netcat-traditional \
          mysql-client rabbitmq-server nginx
RUN DEBIAN_FRONTEND=noninteractive apt-get clean
RUN DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq
RUN mkdir /rematch_server
WORKDIR /rematch_server
ADD ./server/ ./server/
ADD ./tests/server/ ./tests/server/
RUN pip install --upgrade pip
RUN pip install -r /rematch_server/server/requirements.txt --prefer-binary
RUN pip install uwsgi
RUN python /rematch_server/server/manage.py collectstatic --settings rematch.settings.docker --noinput
RUN rm /etc/nginx/sites-enabled/default
RUN ln -sf /rematch_server/server/rematch_nginx.conf /etc/nginx/sites-enabled/default
