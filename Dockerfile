FROM node:4.0
ADD ./package.json /src/
RUN cd /src && npm install --production
WORKDIR /src
ADD . /src/
EXPOSE 3000
CMD ["node", "/src/app.js"]
