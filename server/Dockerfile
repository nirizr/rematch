FROM debian:latest
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq tmux git python-dev \
          python-mysqldb build-essential libmysqlclient-dev python-pip \
          python-numpy python-sklearn netcat-traditional libmysqlclient-dev \
          mysql-client-5.5 rabbitmq-server nginx 
RUN pip install --upgrade pip
RUN DEBIAN_FRONTEND=noninteractive apt-get clean
RUN DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq
ENV PYTHONUNBUFFERED 1
RUN mkdir /rematch_server
WORKDIR /rematch_server
ADD . ./
RUN pip install -r /rematch_server/requirements.txt
RUN pip install uwsgi 
RUN python /rematch_server/manage.py collectstatic --noinput
RUN rm /etc/nginx/sites-enabled/default
RUN ln -sf /rematch_server/rematch_nginx.conf /etc/nginx/sites-enabled/default

RUN service nginx start

