package burp.jwt.bruteforce;

import burp.jwt.core.*;
import java.util.*;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Secret Bruteforcer - Tests JWT signatures against common secrets
 */
public class SecretBruteforcer {
    
    private JWTToken token;
    private List<String> secrets;
    private BruteforceCallback callback;
    private volatile boolean running = false;
    
    public interface BruteforceCallback {
        void onProgress(int tested, int total);
        void onSecretFound(String secret, String algorithm);
        void onComplete();
    }
    
    public SecretBruteforcer(JWTToken token) {
        this.token = token;
        this.secrets = new ArrayList<>();
        loadDefaultSecrets();
    }
    
    /**
     * Load default JWT secrets wordlist (1000+ common secrets)
     */
    private void loadDefaultSecrets() {
        // Top 100+ common JWT secrets
        String[] defaultSecrets = {
            "secret", "password", "123456", "12345678", "123456789",
            "0", "1", "2", "3", "test", "admin", "admin123",
            "password123", "root", "toor", "letmein", "welcome",
            "monkey", "dragon", "master", "sunshine", "princess",
            "qwerty", "abc123", "football", "baseball", "soccer",
            "hockey", "rainbow", "shadow", "michael", "ashley",
            "bailey", "passw0rd", "shadow123", "123123", "654321",
            "555555", "666666", "777777", "888888", "999999",
            "iloveyou", "1234", "12345", "123", "1", "0",
            "password1", "password2", "password3", "password4", "password5",
            "admin1", "admin2", "admin123", "admin@123", "admin!@#",
            "your-256-bit-secret", "your-secret-key", "supersecret",
            "verysecret", "topsecret", "classified", "confidential",
            "secret-key", "secret-sauce", "my-secret", "jwt-secret",
            "jwt-key", "auth-secret", "auth-key", "access-secret",
            "refresh-secret", "token-secret", "token-key", "api-secret",
            "api-key", "private-key", "public-key", "encryption-key",
            "decryption-key", "signing-key", "verification-key",
            "mykey", "yourkey", "testkey", "demokey", "samplekey",
            "example", "test123", "demo123", "sample123", "example123",
            "change-me", "changeme", "change_me", "please-change",
            "change-this", "changethis", "change_this", "update-me",
            "updateme", "update_me", "fix-me", "fixme", "fix_me",
            "temporary", "temp", "tmp", "default", "default123",
            "default-password", "defaultpassword", "default_password",
            "no-password", "no-secret", "empty", "blank", "none",
            "null", "undefined", "unknown", "anonymous", "guest",
            "user", "username", "user123", "test-user", "testuser",
            "demo-user", "demouser", "sample-user", "sampleuser",
            "password-reset", "reset-password", "resetpassword",
            "initial-password", "initialpassword", "temp-password",
            "temppassword", "first-time", "firsttime", "setup",
            "config", "configuration", "settings", "options",
            "2024", "2025", "2023", "2022", "2021", "2020",
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
            "monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday", "spring", "summer", "fall", "winter"
        };
        
        Collections.addAll(secrets, defaultSecrets);
    }
    
    /**
     * Add custom secrets to test
     */
    public void addCustomSecrets(List<String> customSecrets) {
        secrets.addAll(customSecrets);
    }
    
    /**
     * Start brute force attack
     */
    public void startBruteforce(BruteforceCallback callback) {
        this.callback = callback;
        running = true;
        
        Thread bruteforceThread = new Thread(() -> {
            performBruteforce();
            running = false;
            if (callback != null) {
                callback.onComplete();
            }
        });
        
        bruteforceThread.setDaemon(true);
        bruteforceThread.start();
    }
    
    /**
     * Perform the actual brute force
     */
    private void performBruteforce() {
        String alg = token.getHeader().getAlg();
        
        if (!isHmacAlgorithm(alg)) {
            return; // Only HMAC algorithms can be brute forced
        }
        
        // Extract header and payload from original token
        String[] parts = token.getOriginalToken().split("\\.");
        if (parts.length < 2) {
            return;
        }
        
        String headerPayload = parts[0] + "." + parts[1];
        
        int tested = 0;
        for (String secret : secrets) {
            if (!running) {
                break;
            }
            
            try {
                String signature = generateHmacSignature(headerPayload, secret, alg);
                
                // Compare with original signature
                if (parts.length > 2 && parts[2].equals(signature)) {
                    if (callback != null) {
                        callback.onSecretFound(secret, alg);
                        running = false;
                        break;
                    }
                }
                
                tested++;
                if (callback != null && tested % 10 == 0) {
                    callback.onProgress(tested, secrets.size());
                }
                
            } catch (Exception e) {
                // Continue on error
            }
        }
    }
    
    /**
     * Generate HMAC signature
     */
    private String generateHmacSignature(String data, String secret, String algorithm) throws Exception {
        String hmacAlgorithm;
        
        switch (algorithm) {
            case "HS256":
                hmacAlgorithm = "HmacSHA256";
                break;
            case "HS384":
                hmacAlgorithm = "HmacSHA384";
                break;
            case "HS512":
                hmacAlgorithm = "HmacSHA512";
                break;
            default:
                return null;
        }
        
        SecretKeySpec keySpec = new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8),
            0,
            secret.length(),
            hmacAlgorithm
        );
        
        Mac mac = Mac.getInstance(hmacAlgorithm);
        mac.init(keySpec);
        
        byte[] signature = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return JWTUtils.base64UrlEncode(signature);
    }
    
    /**
     * Check if algorithm is HMAC-based
     */
    private boolean isHmacAlgorithm(String alg) {
        return alg != null && (alg.equals("HS256") || alg.equals("HS384") || alg.equals("HS512"));
    }
    
    /**
     * Stop brute force
     */
    public void stop() {
        running = false;
    }
    
    /**
     * Check if algorithm can be brute forced
     */
    public boolean canBruteforce() {
        String alg = token.getHeader().getAlg();
        return isHmacAlgorithm(alg);
    }
}
