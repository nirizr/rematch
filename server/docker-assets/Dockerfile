FROM python:3.6
ENV PYTHONUNBUFFERED 1

# Install needed packages
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq \
        nginx postgresql-client && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq && \
    rm -rf /var/lib/apt/lists/*

# Create rematch user and setup environment
RUN mkdir /rematch_server/ && \
    useradd --no-log-init -M -d /rematch_server rematch && \
    chown rematch:rematch -R /rematch_server/
WORKDIR /rematch_server

# Set up logging directory
# nginx directory is unused, bug nginx will refuse to run with write access
RUN mkdir /var/log/rematch/ && \
    chown rematch:rematch -R /var/log/rematch/ && \
    chown rematch:rematch -R /var/lib/nginx/

# Install uwsgi as an additional step to better utilize docker cache
RUN pip install --disable-pip-version-check --no-cache-dir uwsgi

# Install python requirements
COPY ./server/requirements.txt ./requirements.txt
RUN pip install --disable-pip-version-check --no-cache-dir \
        -r ./requirements.txt && \
    rm ./requirements.txt

# Add rematch project files as late as possible to use dockers cache
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/server/ ./server/tests/

# Downgrade to the rematch user and set server up
WORKDIR /rematch_server/server/
# USER rematch
CMD cd /rematch_server/server ; ./docker-assets/entrypoint.sh
