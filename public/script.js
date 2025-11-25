const socket = io();

// Setup Alice and Bob on load
window.onload = () => {
    socket.emit('setup_user', 'Alice');
    socket.emit('setup_user', 'Bob');
};

// Send Message Function
function sendMessage(from, to) {
    const inputId = `input-${from.toLowerCase()}`;
    const input = document.getElementById(inputId);
    const text = input.value;
    if (!text) return;

    // Optimistic UI update (show sent bubble immediately)
    addChatBubble(from, text, 'sent');
    
    // Send to server
    socket.emit('send_message', { from, to, text });
    input.value = '';
}

// Receive Message (from Server confirmation)
socket.on('message_delivered', (data) => {
    addChatBubble(data.to, data.decrypted, 'received');
});

// Helper: Add Bubble
function addChatBubble(user, text, type) {
    const chatDiv = document.getElementById(`chat-${user.toLowerCase()}`);
    const bubble = document.createElement('div');
    bubble.className = `bubble ${type}`;
    bubble.innerText = text;
    chatDiv.appendChild(bubble);
    chatDiv.scrollTop = chatDiv.scrollHeight;
}

// Wire Traffic Logger
socket.on('wire_traffic', (data) => {
    const logDiv = document.getElementById('wire-log');
    const entry = document.createElement('div');
    entry.className = 'log-entry wire';
    
    entry.innerHTML = `
        <div style="color:white"><strong>[${data.from} → ${data.to}]</strong> Encrypted Packet</div>
        <div> Ciphertext Size: ${data.wireData.cipherLen} bytes</div>
        <div> Ratchet Key: <span class="highlight">${data.wireData.ratchetKeyFragment}</span> (Chain #${data.wireData.chainIndex})</div>
        <div> Gov Encryption: <span style="color:#ff7675">VERIFIED</span> (vGov: ${data.wireData.govKeyFragment})</div>
    `;
    
    logDiv.appendChild(entry);
    logDiv.scrollTop = logDiv.scrollHeight;
});

socket.on('system_log', (msg) => {
    const logDiv = document.getElementById('wire-log');
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerText = `[SYSTEM] ${msg}`;
    logDiv.appendChild(entry);
});