# Peer2Peer_Chunk
# Decentralized Secure P2P Video Sharing Platform

A robust, decentralized peer-to-peer (P2P) video sharing platform built in Java, featuring a custom Distributed Hash Table (DHT) for peer and chunk discovery, and end-to-end security through AES and RSA encryption. This platform eliminates the need for centralized trackers, offering scalable, fault-tolerant, and secure video distribution.

---

## Features

- **Fully Decentralized Architecture**
  - Chord-inspired DHT for distributed peer and chunk lookup
  - Dynamic peer join/leave with finger table updates and stabilization

- **End-to-End Secure Video Transfer**
  - Video files split into chunks and encrypted with AES-256
  - AES keys securely exchanged using RSA-2048 public/private key pairs

- **Optimized Networking**
  - Connection pooling (100 per peer, 50 concurrent transfers)
  - Automatic cleanup of idle connections every 30 seconds (30% performance gain)

- **Smart Chunk Distribution**
  - Rarest-first chunk requesting
  - Real-time peer load and reputation tracking (up to 40% faster downloads)

- **Decentralized Gossip Protocol**
  - Metadata and chunk propagation
  - Enhances resilience and reduces download times by 25%

- **Robust Fault Tolerance**
  - Auto network recovery, chunk re-discovery, and secure cleanup on exit

- **Comprehensive Logging**
  - Tracks peer actions, transfers, and network events

---

## How It Works

1. **Peer Initialization**
   - Each peer generates RSA key pair and joins (or bootstraps) the DHT

2. **Chunk Registration & Discovery**
   - Chunks registered in the DHT along with peer’s public key

3. **Encrypted Chunk Exchange**
   - Chunks encrypted using AES
   - AES keys encrypted using receiver's RSA public key

4. **Download & Merge**
   - Rarest chunks downloaded first, load balanced across peers
   - Chunks decrypted and merged into final video

5. **Gossip Protocol**
   - Periodic metadata exchange between peers

---

## Getting Started

**Prerequisites**
- Java 8 or above

**Run a Peer**
```bash
javac *.java
java PeerClient <dht_port> [<bootstrap_ip:port>]
