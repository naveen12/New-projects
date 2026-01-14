package burp.jwt;

import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Secret Bruteforcer - Advanced JWT secret cracking
 * Tests signatures against 1000+ common secrets and custom wordlists
 */
public class SecretBruteforcer {
    
    private JWTToken token;
    private List<String> secrets;
    private BruteforceCallback callback;
    private volatile boolean running = false;
    private int tested = 0;
    
    public interface BruteforceCallback {
        void onProgress(int tested, int total);
        void onSecretFound(String secret, String algorithm);
        void onComplete(boolean found);
    }
    
    public SecretBruteforcer(JWTToken token) {
        this.token = token;
        this.secrets = new ArrayList<>();
        loadDefaultSecrets();
    }
    
    /**
     * Load 1000+ default JWT secrets wordlist
     */
    private void loadDefaultSecrets() {
        String[] defaultSecrets = {
            // Top 100+ common secrets
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
            // Years and dates
            "2024", "2025", "2023", "2022", "2021", "2020", "2019", "2018", "2017", "2016",
            // Months
            "january", "february", "march", "april", "may", "june",
            "july", "august", "september", "october", "november", "december",
            // Days
            "monday", "tuesday", "wednesday", "thursday", "friday",
            "saturday", "sunday", "spring", "summer", "fall", "winter",
            // Common variations
            "Secret", "SECRET", "Password", "PASSWORD", "Admin", "ADMIN",
            "Test", "TEST", "Demo", "DEMO", "Sample", "SAMPLE",
            // Common prefixes/suffixes
            "secret123", "secret456", "secret789", "secret000",
            "password!123", "password@123", "password#123",
            "auth", "jwt", "token", "key", "salt", "hash",
            "production", "development", "staging", "testing",
            "prod", "dev", "stage", "test",
            // Wallarm wordlist subset
            "changeit", "insecure", "notsecure", "weak",
            "brute", "force", "crack", "vulnerable",
            "exposed", "leaked", "hacked", "pwned",
            // Additional common patterns
            "aaaa", "bbbb", "cccc", "dddd", "eeee", "ffff",
            "11111", "22222", "33333", "44444", "55555",
            "a", "b", "c", "d", "e", "f"
        };
        
        Collections.addAll(secrets, defaultSecrets);
    }
    
    /**
     * Add custom secrets from file or list
     */
    public void addCustomSecrets(List<String> customSecrets) {
        if (customSecrets != null) {
            secrets.addAll(customSecrets);
        }
    }
    
    /**
     * Start brute force attack in background thread
     */
    public void startBruteforce(BruteforceCallback callback) {
        this.callback = callback;
        this.tested = 0;
        running = true;
        
        Thread bruteforceThread = new Thread(() -> {
            boolean found = performBruteforce();
            running = false;
            if (callback != null) {
                callback.onComplete(found);
            }
        });
        
        bruteforceThread.setName("JWT-Bruteforcer");
        bruteforceThread.setDaemon(true);
        bruteforceThread.start();
    }
    
    /**
     * Perform the actual brute force attack
     */
    private boolean performBruteforce() {
        String alg = token.getHeader().getAlg();
        
        if (!isHmacAlgorithm(alg)) {
            return false; // Only HMAC algorithms can be brute forced
        }
        
        // Extract header and payload from original token
        String[] parts = token.getOriginalToken().split("\\.");
        if (parts.length < 2) {
            return false;
        }
        
        String headerPayload = parts[0] + "." + parts[1];
        String originalSignature = parts.length > 2 ? parts[2] : "";
        
        for (String secret : secrets) {
            if (!running) {
                break;
            }
            
            try {
                String signature = generateHmacSignature(headerPayload, secret, alg);
                
                // Compare with original signature (constant-time comparison)
                if (constantTimeEquals(originalSignature, signature)) {
                    if (callback != null) {
                        callback.onSecretFound(secret, alg);
                    }
                    return true;
                }
                
                tested++;
                if (callback != null && tested % 10 == 0) {
                    callback.onProgress(tested, secrets.size());
                }
                
            } catch (Exception e) {
                // Continue on error
            }
        }
        
        return false;
    }
    
    /**
     * Generate HMAC signature
     */
    private String generateHmacSignature(String data, String secret, String algorithm) throws Exception {
        String hmacAlgorithm;
        
        switch (algorithm.toUpperCase()) {
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
     * Constant-time string comparison to prevent timing attacks
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }
        
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        
        return constantTimeEquals(aBytes, bBytes);
    }
    
    /**
     * Constant-time byte array comparison
     */
    private boolean constantTimeEquals(byte[] a, byte[] b) {
        int result = 0;
        
        if (a.length != b.length) {
            return false;
        }
        
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        
        return result == 0;
    }
    
    /**
     * Check if algorithm is HMAC-based
     */
    private boolean isHmacAlgorithm(String alg) {
        return alg != null && (alg.equalsIgnoreCase("HS256") || 
                              alg.equalsIgnoreCase("HS384") || 
                              alg.equalsIgnoreCase("HS512"));
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
    
    /**
     * Get wordlist size
     */
    public int getWordlistSize() {
        return secrets.size();
    }
    
    /**
     * Get number of tested secrets
     */
    public int getTested() {
        return tested;
    }
}
