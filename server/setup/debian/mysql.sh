#!/bin/sh

apt-get -yq install mysql-server
apt-get -yq install libmysqlclient-dev
service mysql start

pip install mysql-python --no-cache-dir
mysql -uroot -e "create database rematch;"

