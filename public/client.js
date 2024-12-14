// client.js
var ws;
// Utility functions for cookies, getCookie/setCookie remain the same
function getCookie(name) {
  const matches = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
  return matches ? decodeURIComponent(matches[1]) : undefined;
}

function setCookie(name, value, days=365) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  document.cookie = `${name}=${encodeURIComponent(value)}; path=/; expires=${date.toUTCString()}`;
}

function clearCookies() {
  // To clear specific cookies you know about (like 'username'):
  document.cookie = 'username=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC';

  // If you have more cookies you set, clear them similarly:
  // document.cookie = 'anotherCookie=; path=/; expires=Thu, 01 Jan 1970 00:00:00 UTC';

  // After clearing cookies, reload the page to force re-prompting
  location.reload();
}


// Prompt for username if not set
let username = getCookie('username');
while (username === null || username === undefined || username.trim() === "") {
  // Prompt for the username
  username = prompt("Please enter your name:");
  // If user pressed cancel, prompt again. The loop continues if it's null or empty anyway.
}

// Extract room from URL
const urlParams = new URLSearchParams(window.location.search);
let room = urlParams.get('room');
if (!room) room = 'defaultRoom';

// Show shareable link
const roomLinkInput = document.getElementById('roomLink');
if (roomLinkInput) {
  const link = `${window.location.origin}/?room=${room}`;
  roomLinkInput.value = link;
}

// Key pair and participant map
let myKeyPair;
let participants = {}; // { username: {publicKey: CryptoKey, sharedKey: CryptoKey} }

// Setup Enter to send message
const messageInput = document.getElementById('message');
messageInput.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    sendMessage();
  }
});

// ECDH Key Generation
(async () => {
  myKeyPair = await generateECDHKeyPair();
  // Now that we have the key pair, connect WebSocket
  ws = new WebSocket(`wss://${location.host}`);
  setupWebSocket(ws); // a function that sets up your ws event listeners
})()

async function generateECDHKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256"
    },
    true,
    ["deriveKey", "deriveBits"]
  );
}

function arrayBufferToBase64(buf) {
  let binary = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64) {
  const binaryString = atob(b64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

async function exportPublicKey(key) {
  const spki = await window.crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64(spki);
}

async function importPublicKey(spkiBase64) {
  const spki = base64ToArrayBuffer(spkiBase64);
  return window.crypto.subtle.importKey(
    "spki",
    spki,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

async function deriveSharedKey(privateKey, peerPublicKey) {
  return await window.crypto.subtle.deriveKey(
    {
      name: "ECDH",
      public: peerPublicKey
    },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(key, plaintext) {
  const enc = new TextEncoder();
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  return { iv: arrayBufferToBase64(iv), ciphertext: arrayBufferToBase64(ciphertext) };
}

async function decryptMessage(key, ivBuffer, ciphertextBuffer) {
  const dec = new TextDecoder();
  const plaintext = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
    key,
    ciphertextBuffer
  );
  return dec.decode(plaintext);
}

// For file encryption/decryption, we don't encode/decode text
// We use raw binary data directly
async function encryptFile(key, fileBuffer) {
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    fileBuffer
  );
  return { iv: arrayBufferToBase64(iv), ciphertext: arrayBufferToBase64(ciphertext) };
}

async function decryptFile(key, ivBuffer, ciphertextBuffer) {
  // Decrypt raw binary
  const decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: new Uint8Array(ivBuffer) },
    key,
    ciphertextBuffer
  );
  return decrypted; // ArrayBuffer
}

// WebSocket Setup
function setupWebSocket(ws) {
  ws.addEventListener('open', async () => {
    console.log('WebSocket connected');
    ws.send(JSON.stringify({ type: 'join', room, username }));
  
    // After joining, send our public key
    const pubKeyBase64 = await exportPublicKey(myKeyPair.publicKey);
    ws.send(JSON.stringify({ type: 'pubkey', username, key: pubKeyBase64 }));
  });

  ws.addEventListener('message', async (event) => {
    const data = JSON.parse(event.data);
    if (data.type === 'ping') {
      console.log("ping");
      ws.send(JSON.stringify({ type: 'pong' }));
    }
    if (data.type === 'message') {
      // Decrypt text message
      const { from, ciphertext, iv } = data;
      if (!participants[from] || !participants[from].sharedKey) {
        console.error(`No shared key with ${from}, cannot decrypt`);
        return;
      }
      const decryptedText = await decryptMessage(
        participants[from].sharedKey,
        base64ToArrayBuffer(iv),
        base64ToArrayBuffer(ciphertext)
      );
      addMessage(`${from}: ${decryptedText}`);

    } else if (data.type === 'file') {
      // Decrypt file message
      const { from, ciphertext, iv, filename } = data;
      if (!participants[from] || !participants[from].sharedKey) {
        console.error(`No shared key with ${from}, cannot decrypt`);
        return;
      }
      const decryptedFileBuffer = await decryptFile(
        participants[from].sharedKey,
        base64ToArrayBuffer(iv),
        base64ToArrayBuffer(ciphertext)
      );
      addFileMessage(from, decryptedFileBuffer, filename);

    } else if (data.type === 'allpubkeys') {
      // Existing participants keys
      for (const { username: fromUser, key } of data.keys) {
        if (fromUser !== username) {
          const publicKey = await importPublicKey(key);
          participants[fromUser] = participants[fromUser] || {};
          participants[fromUser].publicKey = publicKey;
          participants[fromUser].sharedKey = await deriveSharedKey(myKeyPair.privateKey, publicKey);
          console.log(`Derived shared key with existing participant ${fromUser}`);
        }
      }

    } else if (data.type === 'pubkey') {
      // New participant's public key
      const { username: fromUser, key } = data;
      if (fromUser === username) return;
      const publicKey = await importPublicKey(key);
      participants[fromUser] = participants[fromUser] || {};
      participants[fromUser].publicKey = publicKey;
      participants[fromUser].sharedKey = await deriveSharedKey(myKeyPair.privateKey, publicKey);
      console.log(`Derived shared key with new participant ${fromUser}`);
    }
  });
}
// Sending Text Messages
async function sendMessage() {
  const text = messageInput.value;
  if (!text.trim()) return;

  // Get all participants that have a sharedKey
  const participantEntries = Object.entries(participants).filter(([uname, p]) => p.sharedKey);
  if (participantEntries.length === 0) {
    console.error("No shared keys established yet. Can't send encrypted message.");
    return;
  }

  // For each participant, encrypt separately and send
  for (const [uname, p] of participantEntries) {
    const { iv, ciphertext } = await encryptMessage(p.sharedKey, text);
    ws.send(JSON.stringify({
      type: 'message',
      to: uname, // target this specific user
      iv,
      ciphertext
    }));
  }

  addMessage(`${username}: ${text}`);
  messageInput.value = '';
}

// Sending Files also needs a similar treatment
async function sendFile() {
  const fileInput = document.getElementById('fileInput');
  if (fileInput.files.length === 0) return;

  const file = fileInput.files[0];
  const arrayBuffer = await file.arrayBuffer();

  const participantEntries = Object.entries(participants).filter(([uname, p]) => p.sharedKey);
  if (participantEntries.length === 0) {
    console.error("No shared keys established yet. Can't send file.");
    return;
  }

  // Encrypt and send to each participant
  for (const [uname, p] of participantEntries) {
    const { iv, ciphertext } = await encryptFile(p.sharedKey, arrayBuffer);
    ws.send(JSON.stringify({
      type: 'file',
      to: uname,
      iv,
      ciphertext,
      filename: file.name
    }));
  }

  // Now display the file on the sender's screen as well
  // Since we have the original arrayBuffer, we can directly show it
  addFileMessage(username, arrayBuffer, file.name);

  fileInput.value = '';
}


// Displaying Messages
function addMessage(msg) {
  const messagesDiv = document.getElementById('messages');
  const msgEl = document.createElement('div');
  msgEl.textContent = msg;
  messagesDiv.appendChild(msgEl);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

function addFileMessage(from, fileBuffer, filename) {
  const messagesDiv = document.getElementById('messages');
  const msgEl = document.createElement('div');

  // Determine MIME type based on file extension (simple heuristic)
  let mimeType = 'application/octet-stream';
  const ext = filename.split('.').pop().toLowerCase();
  if (ext === 'png') mimeType = 'image/png';
  else if (ext === 'jpg' || ext === 'jpeg') mimeType = 'image/jpeg';
  else if (ext === 'gif') mimeType = 'image/gif';
  // Add more as needed

  const blob = new Blob([fileBuffer], { type: mimeType });
  const url = URL.createObjectURL(blob);

  // Create text node for "from sent file: "
  const description = document.createTextNode(`${from} sent file: `);
  msgEl.appendChild(description);

  // Create a download link for the filename
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.textContent = filename;
  link.style.color = 'blue';
  link.style.textDecoration = 'underline';
  msgEl.appendChild(link);

  // If it's an image, display it inline below the link
  if (mimeType.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = url;
    img.style.maxWidth = '200px';   // adjust as needed
    img.style.display = 'block';    // line break after link
    img.style.marginTop = '5px';
    msgEl.appendChild(img);
  }

  messagesDiv.appendChild(msgEl);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
