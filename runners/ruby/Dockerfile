FROM ruby:3.3-slim
WORKDIR /app
COPY Gemfile .
RUN bundle install
COPY run.rb .
WORKDIR /vectors
CMD ["ruby", "/app/run.rb"]
