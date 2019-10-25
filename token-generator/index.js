const { register, listen } = require('push-receiver');
const http = require('http')
const port = 6969;
http.createServer(async (request, response) => {
  credentials = await register(304268967066);
  response.end(credentials.fcm.token);
}).listen(port)
.on('listening', () => console.log('listening on localhost:' + port))
