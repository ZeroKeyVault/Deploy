require('dotenv').config();
const express = require('express');
const http = require('http');
const { ExpressPeerServer } = require('peer');
const WebSocket = require('ws');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

const server = http.createServer(app);
const port = process.env.PORT || 3000;

// PeerJS server configuration
const peerServer = ExpressPeerServer(server, {
  proxied: true,
  debug: process.env.NODE_ENV !== 'production',
  path: '/peerjs',
  concurrent_limit: 5000,
  alive_timeout: 60000,
  key: process.env.PEERJS_KEY || 'secure-peer-key'
});

app.use('/peerjs', peerServer);

// WebSocket server for message relay
const wss = new WebSocket.Server({ server, 
  perMessageDeflate: {
    zlibDeflateOptions: {
      chunkSize: 1024,
      memLevel: 7,
      level: 3
    },
    zlibInflateOptions: {
      chunkSize: 10 * 1024
    },
    threshold: 1024,
    concurrencyLimit: 10
  }
});

// Data stores
const messageStore = new Map();
const publicVaults = new Map();
const usedHashes = new Map(); // hash -> expiry timestamp

// Cleanup expired data every hour
setInterval(cleanupExpiredData, 3600000);

function cleanupExpiredData() {
  const now = Date.now();
  
  // Clean public vaults
  publicVaults.forEach((vault, hash) => {
    if (vault.expiry <= now) {
      messageStore.delete(hash);
      publicVaults.delete(hash);
    }
  });
  
  // Clean used hashes
  usedHashes.forEach((expiry, hash) => {
    if (expiry <= now) {
      usedHashes.delete(hash);
    }
  });
}

wss.on('connection', (ws, req) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`New connection from ${ip}`);
  
  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data);
      
      switch (msg.type) {
        case 'create_public_vault':
          handleCreatePublicVault(ws, msg);
          break;
          
        case 'join_public_vault':
          handleJoinPublicVault(ws, msg);
          break;
          
        case 'relay_message':
          handleRelayMessage(ws, msg);
          break;
          
        case 'fetch_messages':
          handleFetchMessages(ws, msg);
          break;
          
        case 'create_private_vault':
          handleCreatePrivateVault(ws, msg);
          break;
          
        case 'join_private_vault':
          handleJoinPrivateVault(ws, msg);
          break;
          
        default:
          ws.send(JSON.stringify({ 
            type: 'error', 
            message: 'Invalid message type' 
          }));
      }
    } catch (err) {
      console.error('Error processing message:', err);
      ws.send(JSON.stringify({ 
        type: 'error', 
        message: 'Invalid message format' 
      }));
    }
  });
  
  ws.on('close', () => {
    console.log(`Connection closed from ${ip}`);
  });
});

// Handler functions
function handleCreatePublicVault(ws, msg) {
  const publicHash = crypto.randomBytes(32).toString('hex');
  const expiryTime = parseInt(msg.expiryTime) || 86400000; // Default 24 hours
  
  publicVaults.set(publicHash, {
    name: msg.vaultName,
    expiry: Date.now() + expiryTime,
    key: msg.encryptionKey
  });
  
  ws.send(JSON.stringify({ 
    type: 'public_hash', 
    hash: publicHash,
    expiry: expiryTime
  }));
}

function handleJoinPublicVault(ws, msg) {
  if (!publicVaults.has(msg.hash)) {
    return ws.send(JSON.stringify({ 
      type: 'error', 
      message: 'Vault not found' 
    }));
  }
  
  const vault = publicVaults.get(msg.hash);
  ws.send(JSON.stringify({ 
    type: 'vault_joined', 
    name: vault.name,
    expiry: vault.expiry,
    key: vault.key
  }));
}

function handleRelayMessage(ws, msg) {
  if (!messageStore.has(msg.vaultID)) {
    messageStore.set(msg.vaultID, []);
  }
  
  messageStore.get(msg.vaultID).push({
    data: msg.encryptedData,
    timestamp: Date.now()
  });
  
  ws.send(JSON.stringify({ 
    type: 'ack', 
    message: 'Message stored for relay',
    count: messageStore.get(msg.vaultID).length
  }));
}

function handleFetchMessages(ws, msg) {
  const messages = messageStore.get(msg.vaultID) || [];
  ws.send(JSON.stringify({ 
    type: 'vault_messages', 
    messages,
    count: messages.length
  }));
  
  if (msg.deleteAfterFetch) {
    messageStore.delete(msg.vaultID);
  }
}

function handleCreatePrivateVault(ws, msg) {
  const privateHash = crypto.randomBytes(32).toString('hex');
  const expiryTime = parseInt(msg.expiryTime) || 3600000; // Default 1 hour
  
  usedHashes.set(privateHash, Date.now() + expiryTime);
  
  ws.send(JSON.stringify({ 
    type: 'private_hash', 
    hash: privateHash,
    expiry: expiryTime
  }));
}

function handleJoinPrivateVault(ws, msg) {
  if (!usedHashes.has(msg.hash)) {
    return ws.send(JSON.stringify({ 
      type: 'error', 
      message: 'Invalid or expired vault hash' 
    }));
  }
  
  usedHashes.delete(msg.hash);
  ws.send(JSON.stringify({ 
    type: 'vault_joined', 
    name: msg.vaultName,
    key: msg.encryptionKey
  }));
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: process.uptime(),
    vaults: {
      public: publicVaults.size,
      private: usedHashes.size,
      messages: messageStore.size
    }
  });
});

server.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`PeerJS server available at /peerjs`);
  console.log(`WebSocket server available at ws://localhost:${port}`);
});
