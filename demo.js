const { MessengerClient } = require('./messenger.js');
const { generateEG, generateECDSA, signWithECDSA, cryptoKeyToJSON } = require('./lib.js');
const readline = require('readline');

async function runDemo() {
    console.clear();
    console.log("=== SECURE SIGNAL MESSENGER (GOV COMPLIANT) ===");
    console.log("Initializing PKI...\n");

    // 1. Setup Keys
    const caKeyPair = await generateECDSA();
    const govKeyPair = await generateEG();
    
    // 2. Setup Alice & Bob
    const alice = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
    const bob = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
    
    const aliceCert = await alice.generateCertificate('Alice');
    const bobCert = await bob.generateCertificate('Bob');
    
    // 3. Sign & Exchange Certs
    const aliceSig = await signWithECDSA(caKeyPair.sec, JSON.stringify(aliceCert));
    const bobSig = await signWithECDSA(caKeyPair.sec, JSON.stringify(bobCert));
    
    await alice.receiveCertificate(bobCert, bobSig);
    await bob.receiveCertificate(aliceCert, aliceSig);
    console.log("[+] Certificates Exchanged. Secure Channel Ready.\n");

    // 4. Chat Helper
    const simulateChat = async (from, to, fromName, toName, msg) => {
        const [header, ciphertext] = await from.sendMessage(toName, msg);
        
        // UI: Show what the Government/Network sees
        const govKey = await cryptoKeyToJSON(header.vGov);
        console.log(`\n[${fromName}]: "${msg}"`);
        console.log(`   └─ [WIRE]: Ciphertext Len: ${ciphertext.byteLength} | Gov Key (vGov): ...${govKey.x.slice(-6)}`);
        
        const decrypted = await to.receiveMessage(fromName, [header, ciphertext]);
        console.log(`   └─ [${toName}]: Received & Decrypted: "${decrypted}"`);
    };

    // 5. Run Conversation
    await simulateChat(alice, bob, 'Alice', 'Bob', "Hey Bob, did you get the code?");
    await simulateChat(bob, alice, 'Bob', 'Alice', "Yes, it's 1234.");
    await simulateChat(alice, bob, 'Alice', 'Bob', "Great, deleting now.");
    
    console.log("\n=== DEMO FINISHED ===");
}

runDemo();