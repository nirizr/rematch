FROM frolvlad/alpine-miniconda3
ENV PYTHONUNBUFFERED 1
RUN apk add --no-cache nginx postgresql-client uwsgi-python3

# Create rematch user and setup environment
RUN mkdir /rematch_server/
RUN addgroup rematch && adduser -S -D -H -h /rematch_server rematch -G rematch
WORKDIR /rematch_server
ADD --chown=rematch:rematch ./server/ ./server/
ADD --chown=rematch:rematch ./tests/ ./tests/

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/

RUN chown rematch:rematch -R /var/lib/nginx/

# Install python requirements
RUN pip install --no-cache-dir -r /rematch_server/server/requirements.txt

# Downgrade to the rematch user and set server up
# USER rematch
CMD cd /rematch_server/server ; ./docker-assets/docker-entrypoint.sh
