import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.*;
import javax.crypto.SecretKey;

public class PeerClient {
    private static int CHUNK_SIZE;
    private static final int BASE_PORT = 5000;
    private static final Map<Integer, List<String>> chunkOwners = new ConcurrentHashMap<>();
    private static final Set<Integer> receivedChunks = ConcurrentHashMap.newKeySet();
    private static final Set<Integer> requestedChunks = ConcurrentHashMap.newKeySet();
    private static int myPort;
    private static String myIP;
    private static volatile boolean shutdownRequested = false;
    private static final Logger logger = Logger.getLogger(PeerClient.class.getName());
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(5);
    private static final Object mergeLock = new Object();
    private static DatagramSocket udpSocket;
    private static final Map<String, Integer> peerReputation = new ConcurrentHashMap<>();
    private static volatile boolean mergeCompleted = false;
    // New fields for encryption and DHT
    private static KeyPair keyPair;
    private static final Map<String, PublicKey> peerPublicKeys = new ConcurrentHashMap<>();
    private static final Map<Integer, SecretKey> chunkEncryptionKeys = new ConcurrentHashMap<>();
    private static DHTService dhtService;
    private static final int MAX_CONNECTIONS_PER_PEER = 100;
    private static final int MAX_TOTAL_CONNECTIONS = 50;
    private static final int CONNECTION_TIMEOUT = 5000; 
    private static final int SOCKET_TIMEOUT = 30000; 
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long CONNECTION_TTL = 3600000; 
    private static final Map<String, Queue<PooledSocket>> connectionPool = new ConcurrentHashMap<>();
    private static final Map<String, Semaphore> connectionLimits = new ConcurrentHashMap<>();
    private static final AtomicInteger totalConnections = new AtomicInteger(0);
    private static final ScheduledExecutorService connectionCleaner = Executors.newSingleThreadScheduledExecutor();

    
    
    static {
        try {
            FileHandler fileHandler = new FileHandler("peer_" + System.currentTimeMillis() + ".log");
            logger.addHandler(fileHandler);
            SimpleFormatter formatter = new SimpleFormatter();
            fileHandler.setFormatter(formatter);
            logger.setLevel(Level.ALL);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    private static class PooledSocket {
        private final Socket socket;
        private final long creationTime;
        private long lastUsedTime;
        private boolean inUse;
        
        public PooledSocket(Socket socket) {
            this.socket = socket;
            this.creationTime = System.currentTimeMillis();
            this.lastUsedTime = System.currentTimeMillis();
            this.inUse = false;
        }
        
        public Socket getSocket() {
            return socket;
        }
        
        public boolean isValid() {
            return socket != null && !socket.isClosed() && socket.isConnected();
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - creationTime > CONNECTION_TTL;
        }
        
        public boolean isIdle(long idleTimeout) {
            return !inUse && System.currentTimeMillis() - lastUsedTime > idleTimeout;
        }
        
        public void markInUse() {
            inUse = true;
            lastUsedTime = System.currentTimeMillis();
        }
        
        public void markReturned() {
            inUse = false;
            lastUsedTime = System.currentTimeMillis();
        }
    }
    
    // Initialize the connection pool cleaner
    static {
        connectionCleaner.scheduleAtFixedRate(() -> {
            cleanIdleConnections();
        }, 30, 30, TimeUnit.SECONDS);
    }
    
    private static void cleanIdleConnections() {
        logger.fine("Cleaning idle connections from pool");
        int closed = 0;
        
        for (Map.Entry<String, Queue<PooledSocket>> entry : connectionPool.entrySet()) {
            String peer = entry.getKey();
            Queue<PooledSocket> connections = entry.getValue();
            
            synchronized (connections) {
                Iterator<PooledSocket> iterator = connections.iterator();
                while (iterator.hasNext()) {
                    PooledSocket pooledSocket = iterator.next();
                    
                    // Close and remove expired or idle connections
                    if (!pooledSocket.isValid() || pooledSocket.isExpired() || 
                        pooledSocket.isIdle(300000)) { // 5 minutes idle timeout
                        closeSocket(pooledSocket.getSocket());
                        iterator.remove();
                        totalConnections.decrementAndGet();
                        closed++;
                    }
                }
            }
            
            // Remove empty queues
            if (connections.isEmpty()) {
                connectionPool.remove(peer);
                connectionLimits.remove(peer);
            }
        }
        
        if (closed > 0) {
            logger.info("Closed " + closed + " idle or expired connections. Total active: " + totalConnections.get());
        }
    }
    
    private static Socket getConnection(String peer) {
        if (peer == null) {
            logger.warning("Attempted to get connection to null peer");
            return null;
        }
        
        // Initialize connection limit for this peer if not exists
        connectionLimits.putIfAbsent(peer, new Semaphore(MAX_CONNECTIONS_PER_PEER));
        Semaphore limit = connectionLimits.get(peer);
        
        // Initialize connection queue for this peer if not exists
        connectionPool.putIfAbsent(peer, new ConcurrentLinkedQueue<>());
        Queue<PooledSocket> connections = connectionPool.get(peer);
        
        // Try to get an existing connection
        PooledSocket pooledSocket = null;
        synchronized (connections) {
            while (!connections.isEmpty()) {
                pooledSocket = connections.poll();
                
                // Check if the connection is still valid
                if (pooledSocket != null && pooledSocket.isValid() && !pooledSocket.isExpired()) {
                    pooledSocket.markInUse();
                    return pooledSocket.getSocket();
                } else if (pooledSocket != null) {
                    // Close invalid connection
                    closeSocket(pooledSocket.getSocket());
                    totalConnections.decrementAndGet();
                    pooledSocket = null;
                }
            }
        }
        
        // If we reached here, we need to create a new connection
        return createNewConnection(peer, limit);
    }
    
    private static Socket createNewConnection(String peer, Semaphore limit) {
        // Check if we've reached the total connection limit
        if (totalConnections.get() >= MAX_TOTAL_CONNECTIONS) {
            logger.warning("Maximum total connections reached (" + MAX_TOTAL_CONNECTIONS + 
                          "). Cannot create new connection to " + peer);
            return null;
        }
        
        // Try to acquire a permit for this peer
        boolean acquired = false;
        try {
            acquired = limit.tryAcquire(CONNECTION_TIMEOUT, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        }
        
        if (!acquired) {
            logger.warning("Connection limit reached for peer " + peer);
            return null;
        }
        
        // We got a permit, try to create a new connection with retry
        Socket socket = null;
        Exception lastException = null;
        
        for (int attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
            try {
                String[] parts = peer.split(":");
                socket = new Socket();
                socket.setKeepAlive(true);
                socket.setTcpNoDelay(true);
                socket.setSoTimeout(SOCKET_TIMEOUT);
                
                // Connect with timeout
                socket.connect(new InetSocketAddress(parts[0], Integer.parseInt(parts[1])), CONNECTION_TIMEOUT);
                
                // Connection successful
                totalConnections.incrementAndGet();
                logger.fine("Created new connection to " + peer + " (attempt " + (attempt + 1) + 
                           "). Total connections: " + totalConnections.get());
                
                PooledSocket pooledSocket = new PooledSocket(socket);
                pooledSocket.markInUse();
                return socket;
                
            } catch (IOException e) {
                lastException = e;
                logger.warning("Connection attempt " + (attempt + 1) + " to " + peer + " failed: " + e.getMessage());
                
                // Exponential backoff before retry
                if (attempt < MAX_RETRY_ATTEMPTS - 1) {
                    try {
                        Thread.sleep((long) (Math.pow(2, attempt) * 100));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        
        // All attempts failed
        limit.release(); // Release the permit since we failed to create a connection
        logger.severe("Failed to connect to " + peer + " after " + MAX_RETRY_ATTEMPTS + 
                     " attempts: " + (lastException != null ? lastException.getMessage() : "Unknown error"));
        return null;
    }
    
    private static void returnConnection(String peer, Socket socket) {
        if (peer == null || socket == null) {
            return;
        }
        
        // Check if the connection is still valid
        if (socket.isClosed() || !socket.isConnected()) {
            // Connection is invalid, release the permit
            Semaphore limit = connectionLimits.get(peer);
            if (limit != null) {
                limit.release();
            }
            totalConnections.decrementAndGet();
            return;
        }
        
        // Get the connection queue for this peer
        Queue<PooledSocket> connections = connectionPool.get(peer);
        if (connections == null) {
            // Peer was removed from the pool, close the socket
            closeSocket(socket);
            totalConnections.decrementAndGet();
            return;
        }
        
        // Create a new pooled socket and add it to the queue
        PooledSocket pooledSocket = new PooledSocket(socket);
        pooledSocket.markReturned();
        
        synchronized (connections) {
            connections.add(pooledSocket);
        }
        
        logger.fine("Returned connection to " + peer + " to the pool");
    }
    
    private static void closeSocket(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                logger.fine("Error closing socket: " + e.getMessage());
            }
        }
    }
    
    // Method to shut down the connection pool
    private static void shutdownConnectionPool() {
        connectionCleaner.shutdown();
        
        // Close all connections
        for (Queue<PooledSocket> connections : connectionPool.values()) {
            synchronized (connections) {
                for (PooledSocket pooledSocket : connections) {
                    closeSocket(pooledSocket.getSocket());
                }
                connections.clear();
            }
        }
        
        connectionPool.clear();
        connectionLimits.clear();
        totalConnections.set(0);
        
        logger.info("Connection pool shut down");
    }
    public static void main(String[] args) {
        myPort = getAvailablePort();
    int dhtPort = 9100; 
    String bootstrapNode = null; 
    
    if (args.length > 0) {
        try {
            dhtPort = Integer.parseInt(args[0]);
            logger.info("Using DHT port: " + dhtPort);
        } catch (NumberFormatException e) {
            logger.warning("Invalid DHT port specified, using default: " + dhtPort);
        }
    }
    
    if (args.length > 1) {
        bootstrapNode = args[1]; // IP:port of the bootstrap node
        logger.info("Using bootstrap node: " + bootstrapNode);
    }
    
    Runtime.getRuntime().addShutdownHook(new Thread(PeerClient::leaveNetwork));
    
    try {
        // Generate RSA key pair for encryption
        keyPair = CryptoUtils.generateRSAKeyPair();
        logger.info("Generated RSA key pair for secure communication");
        
        // Get the actual network IP instead of localhost
        myIP = getNetworkIP() + ":" + myPort;
        udpSocket = new DatagramSocket(myPort);
        udpSocket.setSoTimeout(1000);
        
        // Initialize DHT service with specified port and bootstrap node
        String localAddress = getNetworkIP();
        dhtService = new DHTService(localAddress, dhtPort, bootstrapNode);
        logger.info("DHT service initialized on port " + dhtPort + 
                    (bootstrapNode != null ? " with bootstrap node " + bootstrapNode : ""));
            
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error initializing peer", e);
            return;
        }
        
        new Thread(() -> startServer(myPort)).start();
        
        // Use DHT instead of centralized tracker
        initializeWithDHT();
        
        startHeartbeat();
        startNetworkMonitor();
        startGossipProtocol();
        
        scheduler.scheduleWithFixedDelay(() -> {
            requestMissingChunks();
            if (isDownloadComplete() && !mergeCompleted) {  // Add check for mergeCompleted
                synchronized (mergeLock) {
                    if (!shutdownRequested && !mergeCompleted) {  // Double-check inside sync block
                        mergeChunks("received_video_" + myPort + ".mp4");
                        mergeCompleted = true;  // Set flag after successful merge
                    }
                }
            }
        }, 2, 5, TimeUnit.SECONDS);
    }
    
    private static String getNetworkIP() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isLoopback() || !networkInterface.isUp()) {
                    continue;
                }
                
                Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            logger.log(Level.SEVERE, "Error getting network IP", e);
        }
        
        // Fallback to localhost if no network interface is found
        return "127.0.0.1";
    }
    
    private static void startServer(int port) {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            logger.info("Peer server started on port " + port);
            while (!shutdownRequested) {
                try {
                    Socket socket = serverSocket.accept();
                    new Thread(new ChunkSender(socket)).start();
                } catch (IOException e) {
                    if (!shutdownRequested) {
                        logger.log(Level.SEVERE, "Error accepting connection", e);
                    }
                }
            }
        } catch (IOException e) {
            logger.log(Level.SEVERE, "IO exception in server thread", e);
        }
    }
    
    private static boolean isDownloadComplete() {
        return receivedChunks.size() == chunkOwners.size() && !chunkOwners.isEmpty();
    }
    
    private static void initializeWithDHT() {
        // For simplicity, we'll use a fixed chunk size
        CHUNK_SIZE = 4096;
        try {
            // For a new peer, we need to get the video file and determine chunks
            File videoFile = new File("video.mp4");
            if (videoFile.exists()) {
                int totalChunks = (int) Math.ceil((double) videoFile.length() / CHUNK_SIZE);
                // Check if this is the first peer in the network
                boolean isFirstPeer = (dhtService.findChunkOwners("chunk_0").isEmpty());
                List<Integer> myAssignedChunks = new ArrayList<>();
                
                if (isFirstPeer) {
                    // First peer gets all chunks
                    logger.info("This appears to be the first peer. Taking ownership of all chunks.");
                    for (int i = 0; i < totalChunks; i++) {
                        myAssignedChunks.add(i);
                    }
                } else {
                    // For subsequent peers, get chunks from active peers in a balanced way
                    // First, discover all existing chunks in the network
                    Map<String, Integer> peerChunkCount = new HashMap<>();
                    Map<String, List<Integer>> peerChunks = new HashMap<>();
                    
                    // Discover all chunks and their owners
                    for (int i = 0; i < totalChunks; i++) {
                        String chunkIdStr = "chunk_" + i;
                        List<DHTNode.PeerInfo> owners = dhtService.findChunkOwners(chunkIdStr);
                        
                        for (DHTNode.PeerInfo owner : owners) {
                            String peerAddress = owner.address + ":" + owner.port;
                            if (!peerAddress.equals(myIP)) {
                                peerChunkCount.putIfAbsent(peerAddress, 0);
                                peerChunkCount.put(peerAddress, peerChunkCount.get(peerAddress) + 1);
                                
                                peerChunks.putIfAbsent(peerAddress, new ArrayList<>());
                                peerChunks.get(peerAddress).add(i);
                            }
                        }
                    }
                    
                    // Sort peers by chunk count (descending)
                    List<Map.Entry<String, Integer>> sortedPeers = new ArrayList<>(peerChunkCount.entrySet());
                    sortedPeers.sort((a, b) -> b.getValue().compareTo(a.getValue()));
                    
                    // Calculate how many chunks to take from each peer for balanced distribution
                    int totalPeers = sortedPeers.size();
                    if (totalPeers > 0) {
                        int chunksPerPeer = totalChunks / totalPeers;
                        int remainder = totalChunks % totalPeers;
                        for (int i = 0; i < totalPeers; i++) {
                            String peerAddress = sortedPeers.get(i).getKey();
                            int chunksToTake = chunksPerPeer + (i < remainder ? 1 : 0);
                            List<Integer> peerChunkList = peerChunks.get(peerAddress);
                            // Take chunks up to the calculated limit
                            for (int j = 0; j < Math.min(chunksToTake, peerChunkList.size()); j++) {
                                myAssignedChunks.add(peerChunkList.get(j));
                            }
                        }
                    }

                    
                    logger.info("Assigned " + myAssignedChunks.size() + " chunks to this peer in a balanced manner");
                }
                
                // Register our chunks with the DHT
                for (int chunkId : myAssignedChunks) {
                    // Register chunk in DHT
                    String chunkIdStr = "chunk_" + chunkId;
                    String[] parts = myIP.split(":");
                    String peerAddress = parts[0];
                    int peerPort = Integer.parseInt(parts[1]);
                    dhtService.registerChunk(
                        chunkIdStr,
                        myIP,
                        peerAddress,
                        peerPort,
                        CryptoUtils.publicKeyToString(keyPair.getPublic())
                    );
                }
                
                // Process my assigned chunks
                if (!myAssignedChunks.isEmpty()) {
                    splitAndStoreChunks("video.mp4", myAssignedChunks);
                    receivedChunks.addAll(myAssignedChunks);
                }
                
                // Discover all chunks in the network
                discoverChunks(totalChunks);
            } else {
                logger.warning("Video file not found. This peer will only serve as a relay.");
                // Try to discover chunks from the network
                discoverChunks(300); // Assume max 300 chunks to cover the 257 chunks
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error initializing with DHT", e);
        }
    }
    
    
    
    private static void discoverChunks(int maxChunks) {
        logger.info("Discovering chunks from the DHT network...");
        System.out.println("\n===== DISCOVERING PEERS AND CHUNKS =====");
        
        int foundChunks = 0;
        Set<String> discoveredPeers = new HashSet<>();
        
        for (int i = 0; i < maxChunks; i++) {
            String chunkId = "chunk_" + i;
            List<DHTNode.PeerInfo> owners = dhtService.findChunkOwners(chunkId);
            if (!owners.isEmpty()) {
                foundChunks++;
                List<String> ownerAddresses = new ArrayList<>();
                for (DHTNode.PeerInfo owner : owners) {
                    String peerAddress = owner.address + ":" + owner.port;
                    ownerAddresses.add(peerAddress);
                    
                    // Print when a new peer is discovered
                    if (!discoveredPeers.contains(peerAddress) && !peerAddress.equals(myIP)) {
                        discoveredPeers.add(peerAddress);
                        System.out.println("New peer discovered: " + peerAddress);
                        System.out.println("  Public key: " + owner.publicKey.substring(0, 20) + "...");
                    }
                    
                    // Store peer's public key
                    try {
                        PublicKey publicKey = CryptoUtils.publicKeyFromString(owner.publicKey);
                        peerPublicKeys.put(peerAddress, publicKey);
                    } catch (Exception e) {
                        logger.log(Level.WARNING, "Failed to process public key for " + peerAddress, e);
                    }
                    
                    // Initialize reputation
                    peerReputation.putIfAbsent(peerAddress, 50);
                }
                
                // Store chunk owners
                chunkOwners.put(i, ownerAddresses);
            }
        }
        
        System.out.println("Discovered " + discoveredPeers.size() + " peers in the network");
        System.out.println("Discovered " + foundChunks + " chunks in the network");
        System.out.println("===========================\n");
        
        logger.info("Discovered " + foundChunks + " chunks in the network");
        
        // If we found no chunks but we're not the first peer, retry after a delay
        if (foundChunks == 0 && !receivedChunks.isEmpty()) {
            logger.warning("No chunks discovered. Will retry in 5 seconds...");
            try {
                Thread.sleep(5000);
                discoverChunks(maxChunks);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }
    
    
    
    private static void startHeartbeat() {
        scheduler.scheduleAtFixedRate(() -> {
            // We don't need to send heartbeats to the tracker anymore
            // Instead, we'll check connections to peers
            for (Map.Entry<String, Queue<PooledSocket>> entry : connectionPool.entrySet()) {
                String peer = entry.getKey();
                Queue<PooledSocket> connections = entry.getValue();
                
                synchronized (connections) {
                    Iterator<PooledSocket> iterator = connections.iterator();
                    while (iterator.hasNext()) {
                        PooledSocket pooledSocket = iterator.next();
                        Socket socket = pooledSocket.getSocket();
                        
                        if (socket == null || socket.isClosed() || !socket.isConnected()) {
                            iterator.remove();
                            continue;
                        }
                        
                        // Only send heartbeat on idle connections
                        if (!pooledSocket.inUse) {
                            try {
                                PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                                out.println("HEARTBEAT");
                            } catch (IOException e) {
                                iterator.remove();
                                closeSocket(pooledSocket.getSocket());
                            }
                        }
                    }
                    
                    // If all connections are gone, remove the peer
                    if (connections.isEmpty()) {
                        connectionPool.remove(peer);
                    }
                }
            }
        }, 5, 10, TimeUnit.SECONDS);
    }
    
    
    private static void startNetworkMonitor() {
        scheduler.scheduleAtFixedRate(() -> {
            if (!isNetworkAvailable()) {
                while (!isNetworkAvailable()) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
                
                reconnectToPeers();
            }
        }, 10, 30, TimeUnit.SECONDS);
    }
    
    private static boolean isNetworkAvailable() {
        try {
            return InetAddress.getByName("8.8.8.8").isReachable(3000);
        } catch (IOException e) {
            return false;
        }
    }
    
    private static void reconnectToPeers() {
        // Rediscover chunks from DHT
        discoverChunks(100);
        // Try to reconnect to known peers
        for (Map.Entry<Integer, List<String>> entry : chunkOwners.entrySet()) {
            for (String peer : entry.getValue()) {
                if (!peer.equals(myIP) && !connectionPool.containsKey(peer)) {
                    getConnection(peer);
                }
            }
        }
    }
    
    
    private static void startGossipProtocol() {
        System.out.println("\n===== STARTING GOSSIP PROTOCOL =====");
        System.out.println("Peer ID: " + myIP + ":" + myPort);
        System.out.println("Initial known peers: " + connectionPool.keySet());
        System.out.println("===========================\n");
        
        scheduler.scheduleAtFixedRate(() -> {
            // Select random peers to gossip with
            List<String> peers = new ArrayList<>(connectionPool.keySet());
            if (peers.isEmpty()) return;
            
            // Print gossip round information
            System.out.println("\n===== GOSSIP ROUND =====");
            System.out.println("Peer " + myIP + ":" + myPort + " gossiping with: " + peers);
            
            for (String peer : peers) {
                try {
                    Socket socket = getConnection(peer);
                    if (socket != null && socket.isConnected()) {
                        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                        String gossipData = encodeOwnershipMap();
                        System.out.println("Sending gossip data to " + peer + ": " + gossipData);
                        out.println("GOSSIP " + gossipData);
                        returnConnection(peer, socket);
                    }
                } catch (IOException ignored) {}
            }
            
            // Print current state after gossip
            printCurrentGossipState();
        }, 20, 30, TimeUnit.SECONDS);
    }
    
    
    // Add this new method to print current gossip state
    private static void printCurrentGossipState() {
        System.out.println("\n===== CURRENT GOSSIP STATE =====");
        System.out.println("Peer: " + myIP + ":" + myPort);
        System.out.println("Known connections: " + connectionPool.keySet());
        System.out.println("Owned chunks: " + receivedChunks);
        System.out.println("Chunk ownership map:");
        for (Map.Entry<Integer, List<String>> entry : chunkOwners.entrySet()) {
            System.out.println("  Chunk " + entry.getKey() + ": " + entry.getValue());
        }
        System.out.println("===========================\n");
    }
    
    
    private static String encodeOwnershipMap() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer, List<String>> entry : chunkOwners.entrySet()) {
            sb.append(entry.getKey()).append(":").append(String.join(",", entry.getValue())).append(";");
        }
        
        return sb.toString();
    }
    
    private static void splitAndStoreChunks(String fileName, List<Integer> assignedChunks) {
        File videoFile = new File(fileName);
        if (!videoFile.exists()) return;
        try (RandomAccessFile fileIn = new RandomAccessFile(videoFile, "r")) {
            for (int chunkId : assignedChunks) {
                long position = (long) chunkId * CHUNK_SIZE;
                if (position >= fileIn.length()) continue;
                int remainingBytes = (int) Math.min(CHUNK_SIZE, fileIn.length() - position);
                byte[] buffer = new byte[remainingBytes];
                fileIn.seek(position);
                int bytesRead = fileIn.read(buffer);
                
                // Generate a new AES key for this chunk
                SecretKey aesKey = CryptoUtils.generateAESKey();
                chunkEncryptionKeys.put(chunkId, aesKey);
                
                // Encrypt the chunk
                byte[] encryptedData = CryptoUtils.encryptWithAES(buffer, aesKey);
                
                File chunkFile = new File("chunk_" + myPort + "_" + chunkId);
                try (FileOutputStream chunkOut = new FileOutputStream(chunkFile)) {
                    chunkOut.write(encryptedData);
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error splitting and storing chunks", e);
        }
    }
    
    private static void requestMissingChunks() {
        Set<Integer> missingChunks = getMissingChunks();
        
        // Sort chunks by rarity (fewest owners first)
        PriorityQueue<Integer> rarestChunks = new PriorityQueue<>(
            Comparator.comparingInt(a -> chunkOwners.get(a).size())
        );
        rarestChunks.addAll(missingChunks);
        
        // Track how many chunks we've requested from each peer to balance load
        Map<String, Integer> peerLoadCount = new ConcurrentHashMap<>();
        
        ExecutorService executor = Executors.newFixedThreadPool(
            Math.max(4, Math.min(10, missingChunks.size()))
        );
        
        while (!rarestChunks.isEmpty()) {
            int chunkId = rarestChunks.poll();
            if (requestedChunks.contains(chunkId)) continue;
            
            requestedChunks.add(chunkId);
            
            executor.submit(() -> {
                List<String> owners = new ArrayList<>(chunkOwners.getOrDefault(chunkId, Collections.emptyList()));
                
                // Sort owners by: 
                // 1. Reputation (higher first)
                // 2. Current load (lower first)
                owners.sort((peer1, peer2) -> {
                    int rep1 = peerReputation.getOrDefault(peer1, 0);
                    int rep2 = peerReputation.getOrDefault(peer2, 0);
                    
                    // If reputation difference is significant, prioritize by reputation
                    if (Math.abs(rep1 - rep2) > 20) {
                        return Integer.compare(rep2, rep1);
                    }
                    
                    // Otherwise, balance load
                    int load1 = peerLoadCount.getOrDefault(peer1, 0);
                    int load2 = peerLoadCount.getOrDefault(peer2, 0);
                    return Integer.compare(load1, load2);
                });
                
                for (String owner : owners) {
                    if (owner.equals(myIP)) continue;
                    
                    // Increment the load counter for this peer
                    peerLoadCount.merge(owner, 1, Integer::sum);
                    
                    if (fetchChunkFromPeer(owner, chunkId)) {
                        receivedChunks.add(chunkId);
                        peerReputation.computeIfPresent(owner, (k, v) -> Math.min(100, v + 5));
                        
                        // Register this chunk in the DHT so other peers know we have it
                        try {
                            String chunkIdStr = "chunk_" + chunkId;
                            String[] parts = myIP.split(":");
                            String peerAddress = parts[0];
                            int peerPort = Integer.parseInt(parts[1]);
                            
                            dhtService.registerChunk(
                                chunkIdStr, 
                                myIP, 
                                peerAddress, 
                                peerPort, 
                                CryptoUtils.publicKeyToString(keyPair.getPublic())
                            );
                        } catch (Exception e) {
                            logger.log(Level.WARNING, "Failed to register chunk " + chunkId, e);
                        }
                        
                        break;
                    } else {
                        // Decrement the load since the request failed
                        peerLoadCount.computeIfPresent(owner, (k, v) -> v - 1);
                        peerReputation.computeIfPresent(owner, (k, v) -> Math.max(0, v - 10));
                    }
                }
                
                requestedChunks.remove(chunkId);
            });
        }
        
        executor.shutdown();
        try {
            // Wait for all chunk requests to complete or timeout after 30 seconds
            executor.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
    
    
    private static Set<Integer> getMissingChunks() {
        Set<Integer> missingChunks = new HashSet<>();
        for (int chunkId : chunkOwners.keySet()) {
            if (!receivedChunks.contains(chunkId)) {
                File chunkFile = new File("chunk_" + myPort + "_" + chunkId);
                if (!chunkFile.exists() || chunkFile.length() == 0) {
                    missingChunks.add(chunkId);
                } else {
                    receivedChunks.add(chunkId);
                }
            }
        }
        return missingChunks;
    }
    
    private static boolean fetchChunkFromPeer(String peer, int chunkId) {
        Socket socket = null;
        boolean success = false;
        
        try {
            socket = getConnection(peer);
            if (socket == null) return false;
            
            socket.setSoTimeout(30000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            
            // Generate a new AES key for this chunk
            SecretKey aesKey = CryptoUtils.generateAESKey();
            
            // Get peer's public key
            PublicKey peerPublicKey = peerPublicKeys.get(peer);
            if (peerPublicKey == null) {
                logger.warning("No public key available for " + peer);
                return false;
            }
            
            // Encrypt the AES key with peer's public key
            byte[] encryptedKey = CryptoUtils.encryptAESKey(aesKey, peerPublicKey);
            
            // Send request with encrypted key
            out.write(("GET_CHUNK " + chunkId + " " +
                    Base64.getEncoder().encodeToString(encryptedKey) + "\n").getBytes());
            out.flush();
            
            // Read encrypted chunk
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[65536];
            int bytesRead;
            
            while ((bytesRead = in.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
                if (bytesRead < buffer.length) break;
            }
            
            byte[] encryptedData = baos.toByteArray();
            
            // Decrypt the chunk
            byte[] decryptedData = CryptoUtils.decryptWithAES(encryptedData, aesKey);
            
            // Save the decrypted chunk
            try (FileOutputStream fileOut = new FileOutputStream("chunk_" + myPort + "_" + chunkId)) {
                fileOut.write(decryptedData);
            }
            
            success = true;
            return true;
        } catch (Exception e) {
            logger.log(Level.WARNING, "Transfer error with " + peer, e);
            return false;
        } finally {
            if (socket != null) {
                if (success) {
                    // Return the connection to the pool if successful
                    returnConnection(peer, socket);
                } else {
                    // Close the connection if there was an error
                    try {
                        socket.close();
                    } catch (IOException ex) {
                        // Ignore
                    }
                }
            }
        }
    }
    
        
    
    

    
    private static void mergeChunks(String outputFileName) {
        if (mergeCompleted) {
            return;
        }
        try {
            // First, check if we have all chunks
            List<Integer> sortedChunks = new ArrayList<>(chunkOwners.keySet());
            Collections.sort(sortedChunks);
            
            // Check for missing chunks
            for (int chunkId : sortedChunks) {
                File chunkFile = new File("chunk_" + myPort + "_" + chunkId);
                if (!chunkFile.exists() || chunkFile.length() == 0) {
                    logger.warning("Missing chunk " + chunkId + " during merge. Will retry later.");
                    return;
                }
            }
            
            logger.info("All " + sortedChunks.size() + " chunks available. Merging into " + outputFileName);
            
            try (FileOutputStream mergedFileOut = new FileOutputStream(outputFileName)) {
                for (int chunkId : sortedChunks) {
                    File chunkFile = new File("chunk_" + myPort + "_" + chunkId);
                    
                    try (FileInputStream chunkIn = new FileInputStream(chunkFile)) {
                        byte[] encryptedData = new byte[(int) chunkFile.length()];
                        chunkIn.read(encryptedData);
                        
                        // Decrypt the chunk if we have the key
                        byte[] decryptedData;
                        if (chunkEncryptionKeys.containsKey(chunkId)) {
                            // This is a chunk we created
                            decryptedData = CryptoUtils.decryptWithAES(encryptedData, chunkEncryptionKeys.get(chunkId));
                        } else {
                            // This is a chunk we downloaded (already decrypted during download)
                            decryptedData = encryptedData;
                        }
                        
                        mergedFileOut.write(decryptedData);
                    }
                }
                
                logger.info("All chunks merged successfully into file: " + outputFileName);
                
                // Verify the merged file size
                File mergedFile = new File(outputFileName);
                logger.info("Merged file size: " + mergedFile.length() + " bytes");
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error merging chunks", e);
        }
    }
    
    
    private static int getAvailablePort() {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        } catch (IOException e) {
            return BASE_PORT + new Random().nextInt(1000);
        }
    }
    
    private static void leaveNetwork() {
        shutdownRequested = true;
        
        // Clean up DHT service
        if (dhtService != null) {
            dhtService.shutdown();
        }
        
        // Delete local chunks
        deleteLocalChunks();
        logger.info("Chunks deleted successfully. Leaving network.");
    }
    
    private static void deleteLocalChunks() {
        File dir = new File(".");
        File[] files = dir.listFiles((d, name) -> name.startsWith("chunk_" + myPort + "_"));
        if (files != null) {
            for (File f : files) {
                if (f.delete()) {
                    logger.info("Deleted chunk file: " + f.getName());
                }
            }
        }
    }
    
    static class ChunkSender implements Runnable {
        private final Socket socket;
        
        public ChunkSender(Socket socket) {
            this.socket = socket;
        }
        
        @Override
        public void run() {
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                OutputStream out = socket.getOutputStream();
                
                String requestLine;
                while ((requestLine = in.readLine()) != null) {
                    if (requestLine.startsWith("GET_CHUNK")) {
                        String[] parts = requestLine.split(" ", 3);
                        int chunkId = Integer.parseInt(parts[1]);
                        
                        // Extract encrypted AES key
                        byte[] encryptedKey = Base64.getDecoder().decode(parts[2]);
                        
                        // Decrypt AES key with our private key
                        SecretKey aesKey = CryptoUtils.decryptAESKey(encryptedKey, keyPair.getPrivate());
                        
                        // Send encrypted chunk
                        sendEncryptedChunk(chunkId, aesKey, out);
                        
                    } else if (requestLine.startsWith("GOSSIP")) {
                        String gossipData = requestLine.substring(7).trim();
                        applyGossipUpdate(gossipData);
                    } else if (requestLine.equals("HEARTBEAT")) {
                        PrintWriter writer = new PrintWriter(out, true);
                        writer.println("OK");
                    } else if (requestLine.equals("CLOSE")) {
                        break;
                    }
                }
            } catch (IOException e) {
                logger.log(Level.FINE, "Connection closed with client", e);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error in chunk sender", e);
            }
        }
        
        private void sendEncryptedChunk(int chunkId, SecretKey aesKey, OutputStream out) throws Exception {
            File requestedChunk = new File("chunk_" + myPort + "_" + chunkId);
            if (!requestedChunk.exists() || requestedChunk.length() == 0) {
                PrintWriter writer = new PrintWriter(out, true);
                writer.println("CHUNK_NOT_FOUND");
                return;
            }
            
            // Read the chunk
            byte[] chunkData;
            try (FileInputStream fileIn = new FileInputStream(requestedChunk)) {
                chunkData = new byte[(int) requestedChunk.length()];
                fileIn.read(chunkData);
            }
            
            // If we have the encryption key for this chunk, we need to decrypt it first
            if (chunkEncryptionKeys.containsKey(chunkId)) {
                chunkData = CryptoUtils.decryptWithAES(chunkData, chunkEncryptionKeys.get(chunkId));
            }
            
            // Encrypt the chunk with the requester's AES key
            byte[] encryptedData = CryptoUtils.encryptWithAES(chunkData, aesKey);
            
            // Send the encrypted chunk
            out.write(encryptedData);
            out.flush();
        }
        
        private void applyGossipUpdate(String data) {
            System.out.println("\n===== RECEIVED GOSSIP DATA =====");
            System.out.println("Received data: " + data);
            
            // Store previous state for comparison
            Map<Integer, List<String>> previousState = new HashMap<>(chunkOwners);
            
            String[] entries = data.split(";");
            for (String entry : entries) {
                if (entry.isEmpty()) continue;
                String[] parts = entry.split(":");
                int chunkId = Integer.parseInt(parts[0]);
                List<String> owners = Arrays.asList(parts[1].split(","));
                chunkOwners.putIfAbsent(chunkId, new ArrayList<>());
                Set<String> current = new HashSet<>(chunkOwners.get(chunkId));
                current.addAll(owners);
                chunkOwners.put(chunkId, new ArrayList<>(current));
                for (String owner : owners) {
                    peerReputation.putIfAbsent(owner, 50);
                }
            }
            
            // Print changes to gossip state
            System.out.println("\nState changes after gossip:");
            for (Integer chunkId : chunkOwners.keySet()) {
                List<String> oldOwners = previousState.getOrDefault(chunkId, Collections.emptyList());
                List<String> newOwners = chunkOwners.get(chunkId);
                
                if (!oldOwners.equals(newOwners)) {
                    System.out.println("Chunk " + chunkId + ": " + oldOwners + " -> " + newOwners);
                }
            }
            System.out.println("===========================\n");
        }
        
    }
}
