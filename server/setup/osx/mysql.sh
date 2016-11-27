#!/bin/bash

brew install mysql
pip install mysql-python --no-cache-dir
brew services start mysql
mysql -uroot -e "create database rematch;"
