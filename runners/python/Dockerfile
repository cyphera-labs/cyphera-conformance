FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache python-3.12 py3.12-pip && rm -rf /var/cache/apk/*
WORKDIR /app
RUN pip install cyphera==0.0.1a10 -q --break-system-packages
COPY run.py .
WORKDIR /vectors
CMD ["python3.12", "/app/run.py"]
