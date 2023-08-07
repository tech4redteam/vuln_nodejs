FROM node:16-alpine

WORKDIR /usr/src/app
COPY index.js package.json /usr/src/app

RUN npm update
RUN npm i
EXPOSE 9999
ENTRYPOINT ["npm", "start"]
