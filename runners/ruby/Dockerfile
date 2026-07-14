FROM cgr.dev/chainguard/wolfi-base@sha256:02dab76bd852a70556b5b2002195c8a5fdab77d323c433bf6642aab080489795
RUN apk add --no-cache ruby-3.3 && gem install bundler --no-document && rm -rf /var/cache/apk/*
WORKDIR /app
COPY Gemfile .
RUN bundle install
COPY run.rb .
WORKDIR /vectors
CMD ["ruby", "/app/run.rb"]
