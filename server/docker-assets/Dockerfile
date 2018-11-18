FROM python:3.6
ENV PYTHONUNBUFFERED 1

# Install needed packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq \
          nginx postgresql-client && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq && \
    rm -rf /var/lib/apt/lists/*

# Create rematch user and setup environment
RUN useradd --no-log-init -m -d /rematch_server rematch
WORKDIR /rematch_server
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/server/ ./server/tests/

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/

RUN chown rematch:rematch -R /var/lib/nginx/

# Install python requirements
RUN pip install --upgrade pip uwsgi
RUN pip install -r /rematch_server/server/requirements.txt

# Downgrade to the rematch user and set server up
WORKDIR /rematch_server/server/
# USER rematch
CMD cd /rematch_server/server ; ./docker-assets/entrypoint.sh
