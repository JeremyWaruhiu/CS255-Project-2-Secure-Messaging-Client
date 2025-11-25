'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Helper: Generate a stable string fingerprint for a DH Public Key.
   * Uses only x and y coordinates to avoid mismatches from metadata (key_ops, etc).
   */
  async getFingerprint (cryptoKey) {
    const jwk = await cryptoKeyToJSON(cryptoKey)
    return jwk.x + '|' + jwk.y
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   * username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG()

    const certificate = {
      username,
      publicKey: this.EGKeyPair.pub
    }
    return certificate
  }

  /**
   * Receive and store another user's certificate.
   *
   * Arguments:
   * certificate: certificate object/dictionary
   * signature: ArrayBuffer
   *
   * Return Type: void
   */
  async receiveCertificate (certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)

    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)

    if (!isValid) {
      throw new Error('Certificate signature invalid!')
    }

    // Store the verified certificate
    this.certs[certificate.username] = certificate
  }

  /**
   * Generate the message to be sent to another user.
   *
   * Arguments:
   * name: string
   * plaintext: string
   *
   * Return Type: Tuple of [dictionary, ArrayBuffer]
   */
  async sendMessage (name, plaintext) {
    if (!this.certs[name]) {
      throw new Error(`No certificate found for ${name}`)
    }

    // Initialize session state if it doesn't exist
    if (!this.conns[name]) {
      this.conns[name] = {
        RK: null, // Root Key
        CKs: null, // Chain Key Sending
        CKr: null, // Chain Key Receiving
        DHs: null, // My DH KeyPair (Sending)
        DHr: this.certs[name].publicKey, // Their DH Public Key (Receiving) - initially their Identity Key
        Ns: 0, // Message Number Sending
        Nr: 0, // Message Number Receiving
        PN: 0, // Previous Chain Length
        skippedKeys: {} // Storage for skipped message keys
      }
    }

    const state = this.conns[name]
    const header = {}

    // --- Double Ratchet: DH Step ---
    // If we have no sending chain key (start of session or after receiving a reply),
    // we initiate a new ratchet step.
    if (!state.CKs) {
      // 1. Generate new ephemeral keypair
      state.DHs = await generateEG()

      // 2. Perform DH calculations
      if (state.RK === null) {
        // Initial Session Setup
        const dh1 = await computeDH(this.EGKeyPair.sec, state.DHr)
        const dh2 = await computeDH(state.DHs.sec, state.DHr)
        // Combine them via HKDF (Using standard info string "ratchet-init")
        // We treat the output of HKDF as [RootKey, ChainKeySending]
        const kdfOut = await HKDF(dh1, dh2, 'ratchet-init')
        state.RK = kdfOut[0]
        state.CKs = kdfOut[1]
        state.PN = 0
      } else {
        // Standard Ratchet Step
        state.PN = state.Ns // Capture the previous chain length BEFORE resetting Ns
        const sharedSecret = await computeDH(state.DHs.sec, state.DHr)
        const kdfOut = await HKDF(state.RK, sharedSecret, 'ratchet-dh')
        state.RK = kdfOut[0]
        state.CKs = kdfOut[1]
      }
      // Reset sending count for the new chain
      state.Ns = 0
    }

    // Populate Header with our current Ratchet Public Key
    header.dhPub = state.DHs.pub
    header.N = state.Ns
    header.PN = state.PN

    // --- Double Ratchet: Symmetric Key Step ---
    // Derive Message Key (MK) and Next Chain Key (CKs)

    // 1. Derive the actual message key (CryptoKey) for encryption
    const mk = await HMACtoAESKey(state.CKs, 'ratchet-msg-key')

    // 2. Derive the RAW bytes of the SAME message key for the government
    const mkRaw = await HMACtoAESKey(state.CKs, 'ratchet-msg-key', true)

    // 3. Advance the sending chain
    state.CKs = await HMACtoHMACKey(state.CKs, 'ratchet-chain-key')
    state.Ns++ // Increment Sending Count

    // --- Government Encryption ---
    // Encrypt the sending key (mkRaw) for the government.
    const govPair = await generateEG()
    header.vGov = govPair.pub
    header.ivGov = genRandomSalt()

    // Generate Gov AES Key
    const govDH = await computeDH(govPair.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govDH, govEncryptionDataStr)

    header.cGov = await encryptWithGCM(
      govAESKey,
      mkRaw,
      header.ivGov
    )

    // --- Message Encryption ---
    header.receiverIV = genRandomSalt()

    // Authenticate the header
    const headerStr = JSON.stringify(header)
    const ciphertext = await encryptWithGCM(mk, plaintext, header.receiverIV, headerStr)

    return [header, ciphertext]
  }

  /**
   * Decrypt a message received from another user.
   *
   * Arguments:
   * name: string
   * [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
   *
   * Return Type: string
   */
  async receiveMessage (name, [header, ciphertext]) {
    if (!this.certs[name]) {
      throw new Error(`No certificate found for ${name}`)
    }

    // Initialize session state if it doesn't exist (First message received)
    if (!this.conns[name]) {
      const senderCert = this.certs[name]
      this.conns[name] = {
        RK: null,
        CKs: null,
        CKr: null,
        DHs: this.EGKeyPair, // My Identity Key (initially)
        DHr: null, // Will be populated from header
        Ns: 0,
        Nr: 0,
        PN: 0,
        skippedKeys: {}
      }

      const state = this.conns[name]

      // Perform Initial Handshake logic
      state.DHr = header.dhPub
      const dh1 = await computeDH(this.EGKeyPair.sec, senderCert.publicKey)
      const dh2 = await computeDH(this.EGKeyPair.sec, state.DHr)

      const kdfOut = await HKDF(dh1, dh2, 'ratchet-init')
      state.RK = kdfOut[0]
      state.CKr = kdfOut[1]
      state.Nr = 0
    }

    const state = this.conns[name]

    // --- 1. Check for Skipped Keys (Out-of-Order Handling) ---
    // Before processing, check if we already stored a key for this message
    const headerDhFingerprint = await this.getFingerprint(header.dhPub)
    const skipKeyIndex = headerDhFingerprint + '_' + header.N

    if (state.skippedKeys[skipKeyIndex]) {
      const mk = state.skippedKeys[skipKeyIndex]
      delete state.skippedKeys[skipKeyIndex]
      return this.decryptWithKey(mk, header, ciphertext)
    }

    // --- 2. Check for DH Ratchet (Forward chain advancement) ---
    // Check if the sender has a new ratchet key (indicating a ratchet step)
    let ratchetNeeded = false
    if (state.RK !== null) {
      const existingDhFingerprint = await this.getFingerprint(state.DHr)
      // If header key is different from what we have, it means they ratcheted
      if (existingDhFingerprint !== headerDhFingerprint) {
        ratchetNeeded = true
      }
    }

    if (ratchetNeeded) {
      // A. Skip messages in the PREVIOUS chain
      // header.PN tells us how many messages they sent in the chain we are currently on.
      // We fast-forward state.Nr up to header.PN to fill in missing keys.
      if (state.CKr !== null) {
        await this.skipMessageKeys(state, state.DHr, state.Nr, header.PN)
      }

      // B. Perform DH Ratchet
      state.DHr = header.dhPub // Update receiving ratchet key
      const sharedSecret = await computeDH(state.DHs.sec, state.DHr)
      const kdfOut = await HKDF(state.RK, sharedSecret, 'ratchet-dh')
      state.RK = kdfOut[0]
      state.CKr = kdfOut[1]

      // Reset receiving number for the new chain
      state.Nr = 0

      // Wipe sending chain because we received a new key; we must reply with a new one.
      state.CKs = null
    }

    // --- 3. Skip messages in CURRENT chain ---
    // If header.N is greater than our current state.Nr, we skipped messages in this chain.
    await this.skipMessageKeys(state, state.DHr, state.Nr, header.N)

    // --- 4. Process the current message ---
    // Derive MK and next CKr
    const mk = await HMACtoAESKey(state.CKr, 'ratchet-msg-key')
    state.CKr = await HMACtoHMACKey(state.CKr, 'ratchet-chain-key')
    state.Nr++

    return this.decryptWithKey(mk, header, ciphertext)
  }

  /**
   * Helper: Fast-forward the chain and store keys for skipped messages.
   */
  async skipMessageKeys (state, dhPubKey, currentNr, targetNr) {
    if (currentNr >= targetNr) return

    const dhKeyFingerprint = await this.getFingerprint(dhPubKey)

    // Generate keys for every missed message index
    for (let i = currentNr; i < targetNr; i++) {
      const mk = await HMACtoAESKey(state.CKr, 'ratchet-msg-key')
      state.CKr = await HMACtoHMACKey(state.CKr, 'ratchet-chain-key')

      // Store key
      const index = dhKeyFingerprint + '_' + i
      state.skippedKeys[index] = mk
    }
    state.Nr = targetNr
  }

  /**
   * Helper: Perform decryption with error handling
   */
  async decryptWithKey (mk, header, ciphertext) {
    try {
      const headerStr = JSON.stringify(header)
      const plaintextBuffer = await decryptWithGCM(
        mk,
        ciphertext,
        header.receiverIV,
        headerStr
      )
      return bufferToString(plaintextBuffer)
    } catch (err) {
      throw new Error('Decryption failed or tampering detected')
    }
  }
};

module.exports = {
  MessengerClient
}
