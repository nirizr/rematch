FROM python:3.6
ENV PYTHONUNBUFFERED 1
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --fix-missing -yq \
          nginx postgresql-client && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -yq && \
    rm -rf /var/lib/apt/lists/*

# Create rematch user and setup environment
RUN mkdir /rematch_server/
RUN useradd --no-log-init -M -d /rematch_server rematch
WORKDIR /rematch_server

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/
RUN chown rematch:rematch -R /var/lib/nginx/

# Install uwsgi as an additional step to better utilize docker cache
RUN pip install --disable-pip-version-check --no-cache-dir uwsgi

# Install python requirements
COPY ./server/requirements.txt ./requirements.txt
RUN pip install --disable-pip-version-check --no-cache-dir -r ./requirements.txt && \
    rm ./requirements.txt

# Add code to the docker
ADD --chown=rematch:rematch ./server/ ./server/

# Add tests to the docker (TODO: this may be skipped)
ADD --chown=rematch:rematch ./tests/server/ ./server/tests/

# Downgrade to the rematch user and set server up
WORKDIR /rematch_server/server
USER rematch
CMD ./docker-assets/entrypoint.sh
