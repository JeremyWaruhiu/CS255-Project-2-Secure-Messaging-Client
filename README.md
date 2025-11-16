# CS255 Project 2: Secure Messaging Client

## Overview
This project implements a secure messaging client as part of the CS255 course. It demonstrates:

- Certificate-based authentication between peers.
- Symmetric key ratchet for forward secrecy.
- Out-of-order message handling with skipped keys.
- Government encryption simulation using ephemeral keys.
- Replay attack protection.

The implementation follows a simplified Double Ratchet-like scheme focusing on symmetric ratchets for per-message key derivation.  

## Project Structure


w24_proj2_source/
├── lib.js             - Cryptographic primitive wrappers<br>
├── messenger.js       - Main implementation file<br>
├── question6code/     - ECDSA and RSA test scripts for Question 6<br>
├── package.json       - Project dependencies and scripts<br>
├── package-lock.json  - Locked versions for dependencies<br>
└── test/              - Test suite<br>


## Installation

1. Install Node.js (version 18+ recommended).
2. Run the following commands in the project root:


npm install
npm test


All tests, including extra credit for shuffled messages and ratchet handling, should pass.

## Usage

The MessengerClient class supports:

- Generating and receiving certificates.
- Sending and receiving encrypted messages.
- Handling out-of-order messages with skipped keys.

Refer to est/test-messenger.js for usage examples.

## Notes

- This repository is for submission purposes and demonstrates the concepts taught in CS255: Computer Security and Cryptography.
- The code is fully functional with all core and extra credit tests passing.
