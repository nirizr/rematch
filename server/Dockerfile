FROM debian:latest
 ENV PYTHONUNBUFFERED 1
 RUN mkdir /code
 WORKDIR /code
 ADD requirements.txt /code/
 RUN apt-get update && apt-get -y install python python-pip python-sklearn libmysqlclient-dev mysql-server
 RUN pip install -r requirements.txt
 ADD ./code/
