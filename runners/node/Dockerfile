FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache nodejs-22 npm && rm -rf /var/cache/apk/*
WORKDIR /app
COPY package.json .
RUN npm install -q
COPY run.js .
WORKDIR /vectors
CMD ["node", "/app/run.js"]
