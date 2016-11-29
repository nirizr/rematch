FROM debian

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -yq apt-utils coreutils git htop 
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq tmux git python-dev python-mysqldb build-essential libmysqlclient-dev
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq python-pip python-numpy python-sklearn 
RUN pip install --upgrade pip
RUN apt-get clean
WORKDIR /root
RUN git clone -b guy/docker https://github.com/nirizr/rematch.git
WORKDIR /root/rematch/server
RUN DEBIAN_FRONTEND=noninteractive pip install -r requirements.txt 
WORKDIR /root/rematch/server/setup/debian/
RUN DEBIAN_FRONTEND=noninteractive apt-get install -yq mysql-server
RUN DEBIAN_FRONTEND=noninteractive /bin/bash -c "/usr/bin/mysqld_safe &" && ./mysql.sh
WORKDIR /root/rematch/server
EXPOSE 80
RUN DEBIAN_FRONTEND=noninteractive /bin/bash -c "/usr/bin/mysqld_safe &" &&  ./start_server.sh 

