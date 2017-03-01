FROM python:2.7
ENV PYTHONBUFFERED 1
RUN mkdir ./rematch_server
WORKDIR ./rematch_server
ADD ./requirement.txt ./rematch_server
RUN sudo apt-get install python python-pip python-sklearn libmysqlclient-dev mysql-server rabbitmq-server 
RUN sudo pip install -r requirements.txt
ADD ./rematch_server

