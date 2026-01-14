package burp.jwt.analyzer;

import burp.jwt.core.*;
import java.util.*;
import java.util.regex.*;

/**
 * Security Analyzer - 15+ security checks for JWT tokens
 */
public class SecurityAnalyzer {
    
    private JWTToken token;
    private List<SecurityFinding> findings;
    
    // PII patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern PHONE_PATTERN = Pattern.compile("\\b(?:\\+?1[-.]?)?\\(?([0-9]{3})\\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\\b");
    
    // Weak algorithm list
    private static final Set<String> WEAK_ALGORITHMS = new HashSet<>(Arrays.asList(
        "HS256", "HS384", "HS512", "none"
    ));
    
    public SecurityAnalyzer(JWTToken token) {
        this.token = token;
        this.findings = new ArrayList<>();
    }
    
    /**
     * Run all security checks
     */
    public List<SecurityFinding> analyze() {
        findings.clear();
        
        // 1. Algorithm checks
        checkAlgorithmVulnerabilities();
        
        // 2. Claims checks
        checkMissingCriticalClaims();
        checkMissingRecommendedClaims();
        checkClaimValues();
        
        // 3. Sensitive data checks
        checkSensitiveDataExposure();
        
        // 4. Header injection checks
        checkHeaderInjectionVulnerabilities();
        
        // 5. Lifetime and replay checks
        checkTokenLifetime();
        checkReplayAttackVulnerability();
        
        // 6. Additional security checks
        checkWeakSecrets();
        checkTimestampValidation();
        checkJTIValidity();
        
        return findings;
    }
    
    /**
     * Check for algorithm vulnerabilities
     */
    private void checkAlgorithmVulnerabilities() {
        String alg = token.getHeader().getAlg();
        
        if (alg == null) {
            addFinding("Missing Algorithm", 
                      "JWT has no algorithm specified (alg header)",
                      Severity.CRITICAL);
            return;
        }
        
        if (alg.equals("none")) {
            addFinding("None Algorithm Attack",
                      "JWT uses 'none' algorithm - signature verification disabled",
                      Severity.CRITICAL);
        } else if (alg.startsWith("HS")) {
            addFinding("HMAC Algorithm Used",
                      "Token uses symmetric algorithm (HMAC). Vulnerable to algorithm confusion and weak secret attacks.",
                      Severity.HIGH);
        } else if (alg.equals("RS256") || alg.equals("RS384") || alg.equals("RS512")) {
            addFinding("RSA Algorithm Used",
                      "Token uses asymmetric RSA algorithm. Check for algorithm confusion attacks.",
                      Severity.MEDIUM);
        }
    }
    
    /**
     * Check for missing critical claims
     */
    private void checkMissingCriticalClaims() {
        if (!token.hasClaim("exp")) {
            addFinding("Missing Expiration (exp)",
                      "Token has no expiration time - valid indefinitely",
                      Severity.HIGH);
        }
    }
    
    /**
     * Check for missing recommended claims
     */
    private void checkMissingRecommendedClaims() {
        boolean missingIss = !token.hasClaim("iss");
        boolean missingAud = !token.hasClaim("aud");
        boolean missingJti = !token.hasClaim("jti");
        
        if (missingIss || missingAud || missingJti) {
            StringBuilder missing = new StringBuilder();
            if (missingIss) missing.append("iss ");
            if (missingAud) missing.append("aud ");
            if (missingJti) missing.append("jti ");
            
            addFinding("Missing Recommended Claims",
                      "Token missing recommended claims: " + missing.toString().trim(),
                      Severity.MEDIUM);
        }
    }
    
    /**
     * Check claim values for issues
     */
    private void checkClaimValues() {
        Map<String, Object> payload = token.getPayload();
        
        // Check exp value
        if (payload.containsKey("exp")) {
            Object exp = payload.get("exp");
            if (exp instanceof Number) {
                long expTime = ((Number) exp).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                
                if (expTime > currentTime + (365 * 24 * 60 * 60)) {
                    addFinding("Long Token Expiration",
                              "Token valid for more than 1 year - increases risk window",
                              Severity.MEDIUM);
                }
            }
        }
        
        // Check for future dates that are unrealistic
        if (payload.containsKey("exp")) {
            Object exp = payload.get("exp");
            if (exp instanceof Number) {
                long expTime = ((Number) exp).longValue();
                // Year 2100+
                if (expTime > 4102444800L) {
                    addFinding("Unrealistic Expiration",
                              "Token expiration set to year 2100+ - possible bypass attempt",
                              Severity.MEDIUM);
                }
            }
        }
    }
    
    /**
     * Check for sensitive data exposure
     */
    private void checkSensitiveDataExposure() {
        String payloadJson = JWTUtils.mapToJson(token.getPayload());
        List<String> sensitiveData = new ArrayList<>();
        
        // Check for email
        Matcher emailMatcher = EMAIL_PATTERN.matcher(payloadJson);
        while (emailMatcher.find()) {
            sensitiveData.add("Email: " + emailMatcher.group());
        }
        
        // Check for credit card
        Matcher ccMatcher = CREDIT_CARD_PATTERN.matcher(payloadJson);
        while (ccMatcher.find()) {
            sensitiveData.add("Credit Card Pattern");
        }
        
        // Check for SSN
        Matcher ssnMatcher = SSN_PATTERN.matcher(payloadJson);
        while (ssnMatcher.find()) {
            sensitiveData.add("Social Security Number");
        }
        
        // Check for passwords and secrets
        if (payloadJson.toLowerCase().contains("password") || 
            payloadJson.toLowerCase().contains("secret") ||
            payloadJson.toLowerCase().contains("apikey") ||
            payloadJson.toLowerCase().contains("api_key")) {
            sensitiveData.add("Potential password/secret/API key");
        }
        
        if (!sensitiveData.isEmpty()) {
            addFinding("Sensitive Data in Token",
                      "Token contains potentially sensitive data: " + String.join(", ", sensitiveData),
                      Severity.HIGH);
        }
    }
    
    /**
     * Check for header injection vulnerabilities
     */
    private void checkHeaderInjectionVulnerabilities() {
        JWTHeader header = token.getHeader();
        
        // Check kid parameter
        if (header.getKid() != null) {
            String kid = header.getKid();
            if (kid.contains("../") || kid.contains("..\\") || kid.contains("/etc") || kid.contains("C:\\")) {
                addFinding("Path Traversal in KID",
                          "KID parameter may be vulnerable to path traversal attacks",
                          Severity.HIGH);
            }
            if (kid.contains(";") || kid.contains("|") || kid.contains("`")) {
                addFinding("Command Injection in KID",
                          "KID parameter may be vulnerable to command injection",
                          Severity.HIGH);
            }
        }
        
        // Check jku parameter
        if (header.getJku() != null) {
            addFinding("Dynamic JKU URL",
                      "Token uses dynamic JKU URL - potential for SSRF/key injection attacks",
                      Severity.HIGH);
        }
        
        // Check x5u parameter
        if (header.getX5u() != null) {
            addFinding("Dynamic X5U URL",
                      "Token uses dynamic X5U URL - potential for SSRF/key injection attacks",
                      Severity.HIGH);
        }
    }
    
    /**
     * Check token lifetime and expiration
     */
    private void checkTokenLifetime() {
        Long iat = token.getIssuedAt();
        Long exp = token.getExpiration();
        
        if (iat != null && exp != null) {
            long lifetime = exp - iat;
            if (lifetime > (30 * 24 * 60 * 60)) { // 30 days
                addFinding("Long Token Lifetime",
                          "Token lifetime is " + (lifetime / (24 * 60 * 60)) + " days - potential security risk",
                          Severity.MEDIUM);
            }
        }
        
        if (token.isExpired()) {
            addFinding("Token Expired",
                      "This token has already expired",
                      Severity.MEDIUM);
        }
    }
    
    /**
     * Check replay attack vulnerability
     */
    private void checkReplayAttackVulnerability() {
        if (!token.hasClaim("jti")) {
            addFinding("Missing JWT ID (jti)",
                      "Token lacks unique identifier - vulnerable to replay attacks",
                      Severity.MEDIUM);
        }
        
        if (!token.hasClaim("exp")) {
            addFinding("No Expiration - Replay Risk",
                      "Token without expiration can be replayed indefinitely",
                      Severity.HIGH);
        }
    }
    
    /**
     * Check for weak secret vulnerability (for HMAC)
     */
    private void checkWeakSecrets() {
        String alg = token.getHeader().getAlg();
        if (alg != null && alg.startsWith("HS")) {
            addFinding("HMAC Algorithm - Weak Secret Possible",
                      "Token uses HMAC - may be vulnerable to brute force attacks if secret is weak",
                      Severity.MEDIUM);
        }
    }
    
    /**
     * Check timestamp validation issues
     */
    private void checkTimestampValidation() {
        // Check for negative timestamps
        if (token.hasClaim("iat")) {
            Object iat = token.getClaim("iat");
            if (iat instanceof Number && ((Number) iat).longValue() < 0) {
                addFinding("Invalid IAT Timestamp",
                          "Issued-at (iat) timestamp is negative",
                          Severity.MEDIUM);
            }
        }
        
        // Check for nbf (not before)
        if (token.hasClaim("nbf")) {
            Object nbf = token.getClaim("nbf");
            if (nbf instanceof Number) {
                long nbfTime = ((Number) nbf).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                if (nbfTime > currentTime + (365 * 24 * 60 * 60)) {
                    addFinding("NBF in Distant Future",
                              "Not-before (nbf) timestamp is in distant future",
                              Severity.MEDIUM);
                }
            }
        }
    }
    
    /**
     * Check JWT ID validity
     */
    private void checkJTIValidity() {
        if (token.hasClaim("jti")) {
            Object jti = token.getClaim("jti");
            if (jti == null || jti.toString().isEmpty()) {
                addFinding("Empty JWT ID",
                          "JWT ID (jti) claim is empty or null",
                          Severity.LOW);
            }
        }
    }
    
    /**
     * Add a finding
     */
    private void addFinding(String title, String description, Severity severity) {
        findings.add(new SecurityFinding(title, description, severity));
    }
    
    /**
     * Security Severity enum
     */
    public enum Severity {
        CRITICAL(4),
        HIGH(3),
        MEDIUM(2),
        LOW(1),
        INFO(0);
        
        private final int level;
        Severity(int level) { this.level = level; }
        public int getLevel() { return level; }
    }
    
    /**
     * Security Finding class
     */
    public static class SecurityFinding {
        public String title;
        public String description;
        public Severity severity;
        
        public SecurityFinding(String title, String description, Severity severity) {
            this.title = title;
            this.description = description;
            this.severity = severity;
        }
        
        @Override
        public String toString() {
            return "[" + severity + "] " + title + ": " + description;
        }
    }
}
