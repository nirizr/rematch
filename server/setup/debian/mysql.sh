#!/bin/sh


apt-get install mysql-server
apt-get install libmysqlclient-dev

pip install mysql-python --no-cache-dir
mysql -uroot -e "create database rematch;"


