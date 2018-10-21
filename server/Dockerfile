FROM python:3.6
ENV PYTHONUNBUFFERED 1
RUN DEBIAN_FRONTEND=noninteractive apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -qy apt-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq \
          python-dev build-essential python-pip python-numpy python-sklearn \
          netcat-traditional nginx
RUN DEBIAN_FRONTEND=noninteractive apt-get clean
RUN DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq

# Create rematch user and setup environment
RUN useradd --no-log-init -m -d /rematch_server rematch
WORKDIR /rematch_server
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/ ./tests/

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/

RUN chown rematch:rematch -R /var/lib/nginx/

# Install python requirements
RUN pip install --upgrade pip uwsgi librabbitmq
RUN pip install -r /rematch_server/server/requirements.txt

# Downgrade to the rematch user and start server
CMD cd /rematch_server/server ; ./start_docker.sh
