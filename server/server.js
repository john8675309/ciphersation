// server.js
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const url = require('url');

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  if (pathname === '/') {
    let room = parsedUrl.query.room;
    // If no room param, generate one and redirect
    if (!room) {
      room = crypto.randomBytes(3).toString('hex');
      res.writeHead(302, { 'Location': `/?room=${room}` });
      return res.end();
    }

    // Serve index.html
    const fullPath = path.join(__dirname, '../public', 'index.html');
    fs.readFile(fullPath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(404);
        return res.end('Not Found');
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
  } else {
  // For all other paths, serve the file from public
  let filePath = pathname.substring(1);
  const fullPath = path.join(__dirname, '../public', filePath);

  fs.readFile(fullPath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not Found');
    }
    let contentType = 'text/plain';
    if (filePath.endsWith('.html')) contentType = 'text/html';
    else if (filePath.endsWith('.js')) contentType = 'application/javascript';
    else if (filePath.endsWith('.css')) contentType = 'text/css';
    else if (filePath.endsWith('.ico')) contentType = 'image/x-icon';

    res.writeHead(200, { 'Content-Type': contentType });
    res.end(data);
  });
}
});

const wss = new WebSocket.Server({ server });

function heartbeat() {
  this.isAlive = true;
}

let rooms = {};

wss.on('connection', (ws) => {
  let currentRoom = null;
  let currentUser = null;
  ws.on('pong', heartbeat);

  ws.on('message', (message) => {
    let data;
    try {
      data = JSON.parse(message);
    } catch (e) {
      console.error('Invalid JSON', e);
      return;
    }
    if (data.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
    if (data.type === 'join') {
      currentRoom = data.room;
      currentUser = data.username || 'Anonymous';

      if (!rooms[currentRoom]) {
        rooms[currentRoom] = { clients: [], pubkeys: {} };
      }
      rooms[currentRoom].clients.push(ws);
      ws.username = currentUser;

      console.log(`${currentUser} joined room: ${currentRoom}`);

      // Send all known pubkeys to the newly joined user
      const allPubKeys = Object.entries(rooms[currentRoom].pubkeys).map(([u, k]) => ({ username: u, key: k }));
      ws.send(JSON.stringify({ type: 'allpubkeys', keys: allPubKeys }));

    } else if (data.type === 'pubkey') {
      // Store the public key in the room data
      if (currentRoom && currentUser) {
        rooms[currentRoom].pubkeys[currentUser] = data.key;

        // Broadcast this user's public key to others in the room
        rooms[currentRoom].clients.forEach(client => {
          if (client !== ws && client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({
              type: 'pubkey',
              username: currentUser,
              key: data.key
            }));
          }
        });
      }

    } else if (currentRoom && (data.type === 'message' || data.type === 'file')) {
        const roomInfo = rooms[currentRoom];
        if (!roomInfo) return;

        if (data.to) {
          // Send only to the specified user
          roomInfo.clients.forEach(client => {
            if (client.username === data.to && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({
              type: data.type,
              from: ws.username,
              ciphertext: data.ciphertext,
              iv: data.iv,
              filename: data.filename // only if type === 'file'
            }));
          }
        });
        } else {
          // If no 'to' field, broadcast to everyone else (optional behavior)
          roomInfo.clients.forEach(client => {
            if (client !== ws && client.readyState === WebSocket.OPEN) {
              client.send(JSON.stringify({
              type: data.type,
              from: ws.username,
              ciphertext: data.ciphertext,
              iv: data.iv,
              filename: data.filename // only if type === 'file'
            }));
          }
        });
      }
    }
  });

  ws.on('close', () => {
    if (currentRoom && rooms[currentRoom]) {
      rooms[currentRoom].clients = rooms[currentRoom].clients.filter(client => client !== ws);
      delete rooms[currentRoom].pubkeys[currentUser];
      console.log(`${currentUser} left room: ${currentRoom}`);
      if (rooms[currentRoom].clients.length === 0) {
        delete rooms[currentRoom];
      }
    }
  });
});

const interval = setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) {
      console.log('Terminating stale connection');
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => {
  clearInterval(interval);
});


const PORT = 8080;
server.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}/`);
});
