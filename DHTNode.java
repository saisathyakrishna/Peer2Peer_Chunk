import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.*;

public class DHTNode {
    private static final Logger logger = Logger.getLogger(DHTNode.class.getName());
    private static final int M = 160; // SHA-1 hash size
    
    private  String nodeId;
    private  String address;
    private  int port;
    
    private String predecessor;
    private String successor;
    
    // Finger table - for efficient routing
    private final String[] fingerTable = new String[M];
    
    // Store chunk to peer mappings
    private final ConcurrentHashMap<String, Set<String>> chunkToPeers = new ConcurrentHashMap<>();
    
    // Store peer information
    private final ConcurrentHashMap<String, PeerInfo> peerInfoMap = new ConcurrentHashMap<>();
    
    private final ServerSocket serverSocket;
    private boolean running = true;
    
    public DHTNode(String address, int preferredPort) throws IOException {
        this.address = address;
        // Try the preferred port first, then fall back to any available port
        ServerSocket tempSocket = null;
        try {
            tempSocket = new ServerSocket(preferredPort);
            this.port = preferredPort;
        } catch (BindException e) {
            // Preferred port is in use, try to find any available port
            try {
                tempSocket = new ServerSocket(0); // 0 means any available port
                this.port = tempSocket.getLocalPort();
                logger.info("Preferred port " + preferredPort + " was in use. Using port " + this.port + " instead.");
            } catch (IOException e2) {
                logger.severe("Failed to bind to any port: " + e2.getMessage());
                throw e2;
            }
        }
        
        this.serverSocket = tempSocket;
        this.nodeId = generateNodeId(address + ":" + this.port);
        
        // Initialize with self as successor and predecessor
        this.successor = address + ":" + this.port;
        this.predecessor = address + ":" + this.port; // Ensure this is never null
        
        // Initialize finger table
        for (int i = 0; i < M; i++) {
            fingerTable[i] = address + ":" + this.port;
        }
        
        logger.info("DHT Node initialized with ID: " + nodeId + " on port " + this.port);
    }
    
    
    
    public void start() {
        new Thread(this::acceptConnections).start();
        logger.info("DHT Node started listening on port " + port);
    }
    
    private void acceptConnections() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                new Thread(() -> handleConnection(socket)).start();
            } catch (IOException e) {
                if (running) {
                    logger.log(Level.SEVERE, "Error accepting connection", e);
                }
            }
        }
    }
    
    private void handleConnection(Socket socket) {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
            
            String request = in.readLine();
            if (request == null) return;
            
            String[] parts = request.split(" ");
            String command = parts[0];
            
            switch (command) {
                case "JOIN":
                    handleJoin(parts[1], out);
                    break;
                case "FIND_SUCCESSOR":
                    handleFindSuccessor(parts[1], out);
                    break;
                case "NOTIFY":
                if (parts.length > 1 && parts[1] != null && !parts[1].isEmpty()) {
                    handleNotify(parts[1]);
                } else {
                    logger.warning("Received NOTIFY command with missing or invalid parameter");
                }
                break;
                    
                case "STORE_CHUNK":
                    handleStoreChunk(parts[1], parts[2], in, out);
                    break;
                case "FIND_CHUNK":
                    handleFindChunk(parts[1], out);
                    break;
                case "STABILIZE":
                    handleStabilize(out);
                    break;
                case "GET_PREDECESSOR":
                    out.println(predecessor);
                    break;
                default:
                    out.println("UNKNOWN_COMMAND");
            }
            
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error handling connection", e);
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error closing socket", e);
            }
        }
    }
    
    private void handleJoin(String joiningNode, PrintWriter out) {
        String successorNode = findSuccessor(generateNodeId(joiningNode));
        out.println(successorNode);
        logger.info("Node " + joiningNode + " joining, assigned successor: " + successorNode);
        
        // Print DHT table after a new peer joins
        System.out.println("\n===== DHT TABLE AFTER NEW PEER JOIN =====");
        System.out.println("New peer: " + joiningNode);
        System.out.println("Node ID: " + nodeId);
        System.out.println("Predecessor: " + predecessor);
        System.out.println("Successor: " + successor);
        System.out.println("\nFinger Table Entries:");
        for (int i = 0; i < M; i++) {
            System.out.println("Finger[" + i + "]: " + fingerTable[i]);
        }
        System.out.println("===========================\n");
    }
    
    
    private void handleFindSuccessor(String id, PrintWriter out) {
        out.println(findSuccessor(id));
    }
    
    private void handleNotify(String potentialPredecessor) {
        // Add null check
        if (potentialPredecessor == null) {
            logger.warning("Received null potentialPredecessor in handleNotify");
            return;
        }
        
        String potentialPredId = generateNodeId(potentialPredecessor);
        String predId = generateNodeId(predecessor);
        
        // Also check predecessor for null
        if (predecessor == null) {
            predecessor = potentialPredecessor;
            logger.info("Updated predecessor to " + potentialPredecessor);
            return;
        }
        
        if (predecessor.equals(address + ":" + port) ||
            isInRange(potentialPredId, predId, nodeId)) {
            predecessor = potentialPredecessor;
            logger.info("Updated predecessor to " + potentialPredecessor);
        }
    }
    
    
    
    private void handleStoreChunk(String chunkId, String peer, BufferedReader in, PrintWriter out) {
        try {
            // Read peer information
            String peerAddress = in.readLine();
            int peerPort = Integer.parseInt(in.readLine());
            String publicKey = in.readLine();
            
            // Store peer information
            PeerInfo peerInfo = new PeerInfo(peerAddress, peerPort, publicKey);
            peerInfoMap.put(peer, peerInfo);
            
            // Store chunk mapping
            chunkToPeers.computeIfAbsent(chunkId, k -> ConcurrentHashMap.newKeySet()).add(peer);
            
            out.println("OK");
            logger.info("Stored chunk " + chunkId + " for peer " + peer);
        } catch (Exception e) {
            out.println("ERROR " + e.getMessage());
            logger.log(Level.WARNING, "Error storing chunk", e);
        }
    }
    
    private void handleFindChunk(String chunkId, PrintWriter out) {
        Set<String> peers = chunkToPeers.getOrDefault(chunkId, Collections.emptySet());
        
        if (peers.isEmpty()) {
            out.println("NOT_FOUND");
            logger.info("Chunk " + chunkId + " not found");
        } else {
            out.println(peers.size());
            
            for (String peer : peers) {
                PeerInfo peerInfo = peerInfoMap.get(peer);
                if (peerInfo != null) {
                    out.println(peer);
                    out.println(peerInfo.address);
                    out.println(peerInfo.port);
                    out.println(peerInfo.publicKey);
                }
            }
            logger.info("Found " + peers.size() + " peers for chunk " + chunkId);
        }
    }
    
    private void handleStabilize(PrintWriter out) {
        out.println(predecessor);
    }
    
    public String findSuccessor(String id) {
        if (isInRange(id, nodeId, generateNodeId(successor))) {
            return successor;
        } else {
            String closestPrecedingNode = findClosestPrecedingNode(id);
            
            if (closestPrecedingNode.equals(address + ":" + port)) {
                return successor;
            }
            
            try {
                return remoteFindSuccessor(closestPrecedingNode, id);
            } catch (IOException e) {
                logger.log(Level.WARNING, "Error finding remote successor", e);
                return successor;
            }
        }
    }
    
    private String findClosestPrecedingNode(String id) {
        for (int i = M - 1; i >= 0; i--) {
            String fingerId = generateNodeId(fingerTable[i]);
            if (isInRange(fingerId, nodeId, id)) {
                return fingerTable[i];
            }
        }
        return address + ":" + port;
    }
    
    private String remoteFindSuccessor(String node, String id) throws IOException {
        String[] parts = node.split(":");
        String nodeAddress = parts[0];
        int nodePort = Integer.parseInt(parts[1]);
        
        try (Socket socket = new Socket(nodeAddress, nodePort);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            out.println("FIND_SUCCESSOR " + id);
            return in.readLine();
        }
    }
    
    public void join(String bootstrapNode) throws IOException {
        if (bootstrapNode != null && !bootstrapNode.isEmpty() &&
            !bootstrapNode.equals(address + ":" + port)) {
            String[] parts = bootstrapNode.split(":");
            String nodeAddress = parts[0];
            int nodePort = Integer.parseInt(parts[1]);
            try (Socket socket = new Socket(nodeAddress, nodePort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                out.println("JOIN " + address + ":" + port);
                successor = in.readLine();
                predecessor = null;
                logger.info("Joined DHT ring with successor: " + successor);
                
                // Add this code to print DHT table entries
                System.out.println("\n===== DHT TABLE ENTRIES =====");
                System.out.println("Node ID: " + nodeId);
                System.out.println("Predecessor: " + predecessor);
                System.out.println("Successor: " + successor);
                System.out.println("\nFinger Table Entries:");
                for (int i = 0; i < M; i++) {
                    System.out.println("Finger[" + i + "]: " + fingerTable[i]);
                }
                System.out.println("===========================\n");
            }
        } else {
            logger.info("Starting new DHT ring");
            // Also print DHT table for first node
            System.out.println("\n===== DHT TABLE ENTRIES (FIRST NODE) =====");
            System.out.println("Node ID: " + nodeId);
            System.out.println("Predecessor: " + predecessor);
            System.out.println("Successor: " + successor);
            System.out.println("\nFinger Table Entries:");
            for (int i = 0; i < M; i++) {
                System.out.println("Finger[" + i + "]: " + fingerTable[i]);
            }
            System.out.println("===========================\n");
        }
    }
    
    
    public void stabilize() {
        try {
            String[] parts = successor.split(":");
            String successorAddress = parts[0];
            int successorPort = Integer.parseInt(parts[1]);
            
            try (Socket socket = new Socket(successorAddress, successorPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                 BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
                
                out.println("STABILIZE");
                String successorPredecessor = in.readLine();
                
                if (successorPredecessor != null && !successorPredecessor.isEmpty()) {
                    String successorPredId = generateNodeId(successorPredecessor);
                    
                    if (isInRange(successorPredId, nodeId, generateNodeId(successor))) {
                        successor = successorPredecessor;
                        logger.info("Updated successor to " + successorPredecessor);
                    }
                }
                
                notifySuccessor();
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error during stabilize", e);
        }
    }
    
    private void notifySuccessor() {
        try {
            String[] parts = successor.split(":");
            String successorAddress = parts[0];
            int successorPort = Integer.parseInt(parts[1]);
            
            try (Socket socket = new Socket(successorAddress, successorPort);
                 PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {
                
                out.println("NOTIFY " + address + ":" + port);
            }
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error notifying successor", e);
        }
    }
    
    public void fixFingers() {
        for (int i = 0; i < M; i++) {
            String id = calculateFingerID(i);
            fingerTable[i] = findSuccessor(id);
        }
        logger.fine("Fixed finger table");
    }
    
    private String calculateFingerID(int i) {
        BigInteger n = new BigInteger(nodeId, 16);
        BigInteger two = BigInteger.valueOf(2);
        BigInteger offset = two.pow(i);
        BigInteger sum = n.add(offset);
        BigInteger mod = two.pow(M);
        BigInteger result = sum.mod(mod);
        
        return result.toString(16);
    }
    
    public void storeChunk(String chunkId, String peer, String peerAddress, int peerPort, String publicKey) throws IOException {
        String targetNodeId = generateNodeId(chunkId);
        String responsibleNode = findSuccessor(targetNodeId);
        
        String[] parts = responsibleNode.split(":");
        String nodeAddress = parts[0];
        int nodePort = Integer.parseInt(parts[1]);
        
        try (Socket socket = new Socket(nodeAddress, nodePort);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            out.println("STORE_CHUNK " + chunkId + " " + peer);
            out.println(peerAddress);
            out.println(peerPort);
            out.println(publicKey);
            
            String response = in.readLine();
            if (!response.equals("OK")) {
                throw new IOException("Failed to store chunk: " + response);
            }
            logger.info("Successfully stored chunk " + chunkId + " on node " + responsibleNode);
        }
    }
    
    public List<PeerInfo> findChunk(String chunkId) throws IOException {
        String targetNodeId = generateNodeId(chunkId);
        String responsibleNode = findSuccessor(targetNodeId);
        
        String[] parts = responsibleNode.split(":");
        String nodeAddress = parts[0];
        int nodePort = Integer.parseInt(parts[1]);
        
        try (Socket socket = new Socket(nodeAddress, nodePort);
             PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
             BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()))) {
            
            out.println("FIND_CHUNK " + chunkId);
            String response = in.readLine();
            
            if (response.equals("NOT_FOUND")) {
                logger.info("Chunk " + chunkId + " not found in DHT");
                return Collections.emptyList();
            } else {
                int count = Integer.parseInt(response);
                List<PeerInfo> result = new ArrayList<>(count);
                
                for (int i = 0; i < count; i++) {
                    String peer = in.readLine();
                    String peerAddress = in.readLine();
                    int peerPort = Integer.parseInt(in.readLine());
                    String publicKey = in.readLine();
                    
                    result.add(new PeerInfo(peerAddress, peerPort, publicKey));
                }
                
                logger.info("Found " + count + " peers for chunk " + chunkId);
                return result;
            }
        }
    }
    
    public void shutdown() {
        running = false;
        try {
            serverSocket.close();
            logger.info("DHT node shut down");
        } catch (IOException e) {
            logger.log(Level.WARNING, "Error shutting down DHT node", e);
        }
    }
    
    // In DHTNode.java, update the generateNodeId method:
private static String generateNodeId(String input) {
    try {
        // Add stronger null check with logging
        if (input == null || input.isEmpty()) {
            logger.warning("Null or empty input provided to generateNodeId, using default value");
            return "0000000000000000000000000000000000000000"; // Default SHA-1 hash
        }
        
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        
        return sb.toString();
    } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("SHA-1 algorithm not available", e);
    }
}

    
    
    
    private boolean isInRange(String id, String start, String end) {
        // Add null checks
        if (id == null || start == null || end == null) {
            logger.warning("Null parameter in isInRange method");
            return false;
        }
        
        if (start.compareTo(end) < 0) {
            return id.compareTo(start) > 0 && id.compareTo(end) <= 0;
        } else {
            return id.compareTo(start) > 0 || id.compareTo(end) <= 0;
        }
    }
    
    
    public static class PeerInfo {
        public final String address;
        public final int port;
        public final String publicKey;
        
        public PeerInfo(String address, int port, String publicKey) {
            this.address = address;
            this.port = port;
            this.publicKey = publicKey;
        }
    }
}
