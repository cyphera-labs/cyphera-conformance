FROM node:22-slim
WORKDIR /app
COPY package.json .
RUN npm install -q
COPY run.js .
WORKDIR /vectors
CMD ["node", "/app/run.js"]
