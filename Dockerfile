FROM node:20-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY server.js ./
EXPOSE 3100
VOLUME /data
ENV VAULT_DATA=/data
CMD ["node", "server.js"]
