import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DHTService {
    private static final Logger logger = Logger.getLogger(DHTService.class.getName());
    private final DHTNode localNode;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(2);
    
    public DHTService(String localAddress, int localPort, String bootstrapNode) throws IOException {
        localNode = new DHTNode(localAddress, localPort);
        localNode.start();
        
        try {
            if (bootstrapNode != null && !bootstrapNode.isEmpty()) {
                localNode.join(bootstrapNode);
                logger.info("Joined DHT network through bootstrap node: " + bootstrapNode);
            } else {
                logger.info("Started new DHT network");
            }
            
            // Start maintenance tasks
            scheduler.scheduleAtFixedRate(this::stabilize, 5, 10, TimeUnit.SECONDS);
            scheduler.scheduleAtFixedRate(this::fixFingers, 5, 30, TimeUnit.SECONDS);
            
        } catch (IOException e) {
            logger.log(Level.SEVERE, "Failed to join DHT network", e);
            throw e;
        }
    }
    
    private void stabilize() {
        try {
            localNode.stabilize();
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error during stabilize", e);
        }
    }
    
    private void fixFingers() {
        try {
            localNode.fixFingers();
        } catch (Exception e) {
            logger.log(Level.WARNING, "Error during fix fingers", e);
        }
    }
    
    public void registerChunk(String chunkId, String peerId, String peerAddress, int peerPort, String publicKey) {
        try {
            localNode.storeChunk(chunkId, peerId, peerAddress, peerPort, publicKey);
            logger.info("Registered chunk " + chunkId + " for peer " + peerId);
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to register chunk " + chunkId, e);
        }
    }
    
    public List<DHTNode.PeerInfo> findChunkOwners(String chunkId) {
        try {
            List<DHTNode.PeerInfo> owners = localNode.findChunk(chunkId);
            logger.info("Found " + owners.size() + " owners for chunk " + chunkId);
            return owners;
        } catch (IOException e) {
            logger.log(Level.WARNING, "Failed to find owners for chunk " + chunkId, e);
            return Collections.emptyList();
        }
    }
    
    public void shutdown() {
        scheduler.shutdown();
        localNode.shutdown();
        logger.info("DHT service shut down");
    }
}
