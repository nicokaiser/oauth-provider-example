FROM node:0.12
ADD . /src/
WORKDIR /src
RUN cd /src && npm install --production
EXPOSE 3000
CMD ["node", "/src/app.js"]
