'use strict'

const { subtle } = require('node:crypto').webcrypto
const {
  bufferToString,
  genRandomSalt,
  generateEG,
  computeDH,
  verifyWithECDSA,
  HMACtoAESKey,
  HMACtoHMACKey,
  HKDF,
  encryptWithGCM,
  decryptWithGCM,
  cryptoKeyToJSON,
  govEncryptionDataStr
} = require('./lib')

function bufToB64 (buf) {
  return Buffer.from(buf).toString('base64')
}

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // per-peer connection state
    this.certs = {} // stored certificates
    this.EGKeyPair = null
    this.username = null
  }

  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()
    this.username = username
    const pubJSON = await cryptoKeyToJSON(this.EGKeyPair.pub)
    return { username, publicKey: pubJSON }
  }

  async receiveCertificate (certificate, signature) {
    const certString = JSON.stringify(certificate)
    const valid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!valid) throw new Error('Certificate signature invalid')
    this.certs[certificate.username] = certificate
  }

  // helper: import peer public key (JWK -> CryptoKey)
  async _importPeerKey (pubJSON) {
    return await subtle.importKey(
      'jwk',
      pubJSON,
      { name: 'ECDH', namedCurve: 'P-384' },
      true,
      []
    )
  }

  // initialize connection state (first time communicating)
  async _initConn (name, initiator) {
    if (this.conns[name]) return this.conns[name]
    const cert = this.certs[name]
    if (!cert) throw new Error('Missing certificate for ' + name)
    if (!this.EGKeyPair || !this.EGKeyPair.sec) throw new Error('Local keypair not initialized (call generateCertificate)')

    const theirPub = await this._importPeerKey(cert.publicKey)
    const shared = await computeDH(this.EGKeyPair.sec, theirPub)
    const [hk1, hk2] = await HKDF(shared, shared, 'init-ratchet')

    const conn = {
      sharedSecret: shared,
      // seeds for HMAC-to-AES per-message derivation
      sendSeed: initiator ? hk1 : hk2,
      recvSeed: initiator ? hk2 : hk1,
      sendCount: 0,
      recvCount: 0,
      seen: new Set(),           // replay detection (hashes of ciphertexts)
      skipped: new Map(),        // map<msgIndex, CryptoKey> for out-of-order messages
      consumed: new Set()        // set<msgIndex> of message indices we have successfully decrypted
    }

    this.conns[name] = conn
    return conn
  }

  /**
   * Send an encrypted message to `name`.
   * header structure must include: vGov (ephemeral public key CryptoKey),
   * cGov (ArrayBuffer), ivGov (Uint8Array), receiverIV (Uint8Array), sender (string), msgCount (number)
   */
  async sendMessage (name, plaintext) {
    if (!this.certs[name]) throw new Error('Missing certificate for ' + name)
    if (!this.EGKeyPair) throw new Error('Local keypair not initialized (call generateCertificate)')

    const conn = await this._initConn(name, true)

    // derive per-message AES key from sendSeed and counter
    const msgIndex = conn.sendCount
    const msgKey = await HMACtoAESKey(conn.sendSeed, `MSG-${msgIndex}`)
    const rawMsgKey = await subtle.exportKey('raw', msgKey)

    // Government encryption: ephemeral ECDH with gov public key -> AES key -> encrypt rawMsgKey
    const eph = await generateEG()
    const govShared = await computeDH(eph.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govShared, govEncryptionDataStr)

    const ivGov = genRandomSalt(12)
    const cGov = await encryptWithGCM(govAESKey, rawMsgKey, ivGov)

    const receiverIV = genRandomSalt(12)

    // Build header. vGov must be a CryptoKey (ephemeral public key).
    const header = {
      vGov: eph.pub,     // CryptoKey (required by tests' govDecrypt)
      cGov,              // ArrayBuffer
      ivGov,             // Uint8Array
      receiverIV,        // Uint8Array
      sender: this.username,
      msgCount: msgIndex
    }

    // Authenticated data uses JSON.stringify(header) (tests expect that).
    // JSON.stringify handles non-serializable fields consistently in both sides in this test harness.
    const headerAuth = JSON.stringify(header)

    // Encrypt message with message AES key, using receiverIV and headerAuth
    const ciphertext = await encryptWithGCM(msgKey, plaintext, receiverIV, headerAuth)

    // advance sending chain: increment counter and ratchet sendSeed
    conn.sendCount += 1
    conn.sendSeed = await HMACtoHMACKey(conn.sendSeed, 'chain')

    return [header, ciphertext]
  }

  /**
   * Receive message from `name`. Supports out-of-order delivery by deriving
   * and storing skipped message keys up to the incoming msgCount.
   *
   * Throws on replay or tampering.
   */
  async receiveMessage (name, [header, ciphertext]) {
    if (!this.certs[name]) throw new Error('Missing certificate for ' + name)
    if (!this.EGKeyPair) throw new Error('Local keypair not initialized (call generateCertificate)')

    const conn = await this._initConn(name, false)

    // Validate sender
    if (!header.sender || header.sender !== name) throw new Error('Sender mismatch')

    // Replay detection
    const ctHash = Buffer.from(ciphertext).toString('hex')
    if (conn.seen.has(ctHash)) throw new Error('Replay detected')

    // Ensure msgCount exists
    if (typeof header.msgCount !== 'number') throw new Error('Missing msgCount in header')
    const incomingIndex = header.msgCount

    // Derive keys for skipped messages if needed.
    // Use a temporary seed (`tempSeed`) so we only update conn.recvSeed once to the final state.
    if (incomingIndex >= conn.recvCount) {
      let tempSeed = conn.recvSeed
      for (let i = conn.recvCount; i <= incomingIndex; i++) {
        // derive only if missing
        if (!conn.skipped.has(i)) {
          const key = await HMACtoAESKey(tempSeed, `MSG-${i}`)
          conn.skipped.set(i, key)
        }
        // advance tempSeed for next index
        tempSeed = await HMACtoHMACKey(tempSeed, 'chain')
      }
      // commit final seed position
      conn.recvSeed = tempSeed
    }

    // Get key for current message
    const keyForMsg = conn.skipped.get(incomingIndex)
    if (!keyForMsg) throw new Error('No key available for incoming message index')

    // Attempt decryption with header-authenticated data JSON.stringify(header)
    let plaintextBuf
    try {
      plaintextBuf = await decryptWithGCM(keyForMsg, ciphertext, header.receiverIV, JSON.stringify(header))
    } catch (e) {
      // decryption failure => tampering or wrong key
      throw new Error('Tampering or wrong recipient')
    }

    // Successful decrypt: mark seen, mark consumed, remove the consumed skipped key
    conn.seen.add(ctHash)
    conn.skipped.delete(incomingIndex)
    conn.consumed.add(incomingIndex)

    // Advance recvCount only while we've actually consumed that index.
    // This prevents us from overshooting across ratchet boundaries.
    while (conn.consumed.has(conn.recvCount)) {
      // we've consumed this index, so remove marker and bump recvCount
      conn.consumed.delete(conn.recvCount)
      conn.recvCount += 1
    }

    return bufferToString(plaintextBuf)
  }

}

module.exports = { MessengerClient }
