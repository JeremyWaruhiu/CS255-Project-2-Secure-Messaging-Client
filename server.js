// server.js
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { MessengerClient } = require('./messenger.js');
const { generateEG, generateECDSA, signWithECDSA, cryptoKeyToJSON } = require('./lib.js');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public')); // Serve the UI files

// Global State for the Simulation
let caKeyPair, govKeyPair;
let clients = {}; // Stores Alice, Bob, etc.

async function setupSystem() {
    console.log("Initializing System...");
    caKeyPair = await generateECDSA();
    govKeyPair = await generateEG();
}

// Initialize keys on startup
setupSystem();

io.on('connection', (socket) => {
    console.log('Web Client Connected');

    // 1. Handle User Login / Setup
    socket.on('setup_user', async (username) => {
        if (!clients[username]) {
            // Create Client
            const client = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
            const cert = await client.generateCertificate(username);
            const sig = await signWithECDSA(caKeyPair.sec, JSON.stringify(cert));
            
            // Store Client
            clients[username] = { instance: client, cert, sig };
            
            // Auto-exchange certs with existing users
            for (const [otherName, otherData] of Object.entries(clients)) {
                if (otherName !== username) {
                    await client.receiveCertificate(otherData.cert, otherData.sig);
                    await otherData.instance.receiveCertificate(cert, sig);
                }
            }
        }
        socket.emit('system_log', `User '${username}' initialized & Certificates exchanged.`);
    });

    // 2. Handle Message Sending
    socket.on('send_message', async ({ from, to, text }) => {
        try {
            const sender = clients[from].instance;
            const receiver = clients[to].instance;

            // A. Encrypt (Alice sends)
            const [header, ciphertext] = await sender.sendMessage(to, text);

            // Extract Visual Data for the "Wire"
            const govKeyJwk = await cryptoKeyToJSON(header.vGov);
            const wireData = {
                cipherLen: ciphertext.byteLength,
                govKeyFragment: "..." + govKeyJwk.x.slice(-6),
                ratchetKeyFragment: "..." + (await cryptoKeyToJSON(header.dhPub)).x.slice(-6),
                chainIndex: header.N
            };

            // Notify UI of "Wire" traffic
            io.emit('wire_traffic', { from, to, wireData });

            // B. Decrypt (Bob receives)
            const decrypted = await receiver.receiveMessage(from, [header, ciphertext]);

            // Notify UI of success
            io.emit('message_delivered', { from, to, text, decrypted });

        } catch (err) {
            console.error(err);
            socket.emit('error_log', "Error processing message: " + err.message);
        }
    });
});

server.listen(3000, () => {
    console.log('listening on *:3000');
});