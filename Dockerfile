FROM node:20-alpine
WORKDIR /app
COPY package.json server.js ./
COPY public ./public
ENV PORT=3000 HOST=0.0.0.0 DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 3000
USER node
CMD ["node", "server.js"]
