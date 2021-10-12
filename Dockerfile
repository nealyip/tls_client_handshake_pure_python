FROM python:3.9-alpine
MAINTAINER Nealyip

# COPY . /app
RUN apk --no-cache add git libffi-dev gcc musl-dev && \
    git clone https://github.com/nealyip/tls_client_handshake_pure_python.git /app && \
    cd /app && \
    pip install pipenv && \
    pipenv install

WORKDIR /app

ENTRYPOINT ["/usr/local/bin/pipenv", "run", "python", "index.py"]