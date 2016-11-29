FROM debian
MAINTAINER rematch@shift.re

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq apt-utils coreutils git htop 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq tmux git python-dev python-mysqldb build-essential libmysqlclient-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq python-pip python-numpy python-sklearn mysql-server
RUN pip install --upgrade pip
RUN apt-get clean
WORKDIR /root
RUN git clone -b guy/docker https://github.com/nirizr/rematch.git
WORKDIR /root/rematch/server
RUN DEBIAN_FRONTEND=noninteractive pip install -r requirements.txt 
WORKDIR /root/rematch/server/setup/debian/
RUN service mysql start
RUN  pip install mysql-python --no-cache-dir
RUN mysql -uroot -e "create database rematch;"
WORKDIR /root/rematch/server

