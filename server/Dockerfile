FROM debian:latest
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq tmux git python-dev python-mysqldb build-essential libmysqlclient-dev 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq python-pip python-numpy python-sklearn 
RUN pip install --upgrade pip
RUN apt-get clean
ENV PYTHONUNBUFFERED 1
RUN mkdir /rematch_server
WORKDIR /rematch_server
#ADD requirements.txt /rematch_webserver/requirements.txt
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq libmysqlclient-dev  netcat-traditional python-redis mysql-client-5.5
ADD . ./
RUN pip install -r /rematch_server/requirements.txt
CMD DEBIAN_FRONTEND=noninteractive apt-get install -yq rabbitmq-server 
