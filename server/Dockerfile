FROM python:3-alpine
ENV PYTHONUNBUFFERED 1

# Install additiional tools
RUN apk add --no-cache bash nginx postgresql-client

# Create rematch user and setup environment
RUN mkdir /rematch_server/
RUN addgroup rematch && adduser -S -D -H -h /rematch_server rematch -G rematch
WORKDIR /rematch_server

RUN mkdir /var/log/rematch/
RUN chown rematch:rematch -R /var/log/rematch/

RUN chown rematch:rematch -R /var/lib/nginx/

# Install library needed for python requirements
RUN apk add --no-cache --virtual .build-deps build-base \
                                             linux-headers \
                                             gcc \
                                             python3-dev \
                                             freetype-dev \
                                             libpng-dev \
                                             openblas-dev \
                                             postgresql-dev && \
    apk add --no-cache --virtual sklearn-runtime libgfortran libgcc libstdc++ openblas

# Install python requirements
COPY ./server/requirements.txt ./requirements.txt

RUN pip3 install uwsgi && \
    pip3 install --upgrade --no-cache-dir pip -r ./requirements.txt && \
    rm ./requirements.txt

# Ceanup temporary build tools
RUN apk del .build-deps

# Downgrade to the rematch user
USER rematch

# Add code to the docker
ADD --chown=rematch:rematch ./server/ ./server/
WORKDIR /rematch_server/server

# Add tests to the docker (TODO: this may be skipped)
ADD --chown=rematch:rematch ./tests/ ./tests/
CMD ["./docker-assets/docker-entrypoint.sh"]
