FROM node:16-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install pm2 -g

RUN npm install

COPY . .

EXPOSE 5000

CMD ["pm2-runtime", "index.js"]