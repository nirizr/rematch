FROM debian:latest
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq tmux git python-dev python-mysqldb build-essential libmysqlclient-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq python-pip python-numpy python-sklearn 
RUN pip install --upgrade pip
RUN apt-get clean
ENV PYTHONUNBUFFERED 1
RUN mkdir /code
WORKDIR /code
ADD requirements.txt /code/
RUN pip install -r requirements.txt
ADD . ./code/
CMD DEBIAN_FRONTEND=noninteractive apt-get install -yq nc 
