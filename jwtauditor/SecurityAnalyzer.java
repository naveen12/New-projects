package burp.jwt;

import java.util.*;
import java.util.regex.*;

/**
 * Security Analyzer - Comprehensive 15+ security checks for JWT tokens
 * Implements all JWTAuditor analysis features
 */
public class SecurityAnalyzer {
    
    private JWTToken token;
    private List<SecurityFinding> findings;
    
    // PII patterns
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern CREDIT_CARD_PATTERN = Pattern.compile("\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b");
    private static final Pattern SSN_PATTERN = Pattern.compile("\\b\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern PHONE_PATTERN = Pattern.compile("\\b(?:\\+?1[-.]?)?\\(?([0-9]{3})\\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\\b");
    private static final Pattern APIKEY_PATTERN = Pattern.compile("(?:api[_-]?key|apikey|api_secret|secret_key)[\"'\\s:]*[=:][\"'\\s]*([a-zA-Z0-9_-]{20,})");
    
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
        checkHeaderValidation();
        
        return findings;
    }
    
    /**
     * 1. Check for algorithm vulnerabilities
     */
    private void checkAlgorithmVulnerabilities() {
        String alg = token.getHeader().getAlg();
        
        if (alg == null || alg.isEmpty()) {
            addFinding("Missing Algorithm", 
                      "JWT has no algorithm specified (alg header) - Algorithm confusion attack possible",
                      Severity.CRITICAL);
            return;
        }
        
        if (alg.equalsIgnoreCase("none")) {
            addFinding("None Algorithm Attack Vulnerability",
                      "JWT uses 'none' algorithm - signature verification completely disabled",
                      Severity.CRITICAL);
        } else if (alg.startsWith("HS")) {
            addFinding("Weak HMAC Algorithm",
                      "Token uses symmetric algorithm (HMAC). Vulnerable to algorithm confusion attacks and weak secret brute force.",
                      Severity.HIGH);
        } else if (alg.equals("RS256") || alg.equals("RS384") || alg.equals("RS512") ||
                   alg.equals("ES256") || alg.equals("ES384") || alg.equals("ES512")) {
            addFinding("RSA/ECDSA Algorithm Used",
                      "Token uses asymmetric algorithm. Check for algorithm confusion attacks (RS256→HS256).",
                      Severity.MEDIUM);
        } else if (!alg.matches("^(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512|PS256|PS384|PS512)$")) {
            addFinding("Non-Standard Algorithm",
                      "Token uses non-standard algorithm: " + alg,
                      Severity.MEDIUM);
        }
    }
    
    /**
     * 2. Check for missing critical claims
     */
    private void checkMissingCriticalClaims() {
        if (!token.hasClaim("exp")) {
            addFinding("Missing Expiration (exp)",
                      "Token has no expiration time - valid indefinitely. Tokens should expire to limit breach impact.",
                      Severity.CRITICAL);
        }
    }
    
    /**
     * 3. Check for missing recommended claims
     */
    private void checkMissingRecommendedClaims() {
        List<String> missing = new ArrayList<>();
        
        if (!token.hasClaim("iss")) missing.add("iss (Issuer)");
        if (!token.hasClaim("aud")) missing.add("aud (Audience)");
        if (!token.hasClaim("jti")) missing.add("jti (JWT ID)");
        
        if (!missing.isEmpty()) {
            addFinding("Missing Recommended Claims",
                      "Token missing recommended claims: " + String.join(", ", missing) + 
                      " - Increases risk of misuse and replay attacks",
                      Severity.MEDIUM);
        }
    }
    
    /**
     * 4. Check claim values for issues
     */
    private void checkClaimValues() {
        Map<String, Object> payload = token.getPayload();
        
        // Check exp value - unrealistic expiration
        if (payload.containsKey("exp")) {
            Object exp = payload.get("exp");
            if (exp instanceof Number) {
                long expTime = ((Number) exp).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                long daysValid = (expTime - currentTime) / (24 * 60 * 60);
                
                if (expTime > currentTime + (365 * 24 * 60 * 60)) {
                    addFinding("Long Token Expiration",
                              "Token valid for " + daysValid + " days - significantly increases risk window for exploitation",
                              Severity.HIGH);
                }
                
                if (expTime > 4102444800L) { // Year 2100+
                    addFinding("Unrealistic Expiration",
                              "Token expiration set to year 2100+ - possible bypass/test token",
                              Severity.MEDIUM);
                }
            }
        }
    }
    
    /**
     * 5. Check for sensitive data exposure
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
            break;
        }
        
        // Check for SSN
        Matcher ssnMatcher = SSN_PATTERN.matcher(payloadJson);
        while (ssnMatcher.find()) {
            sensitiveData.add("Social Security Number");
            break;
        }
        
        // Check for API keys and passwords
        if (payloadJson.toLowerCase().contains("password")) {
            sensitiveData.add("Password field detected");
        }
        if (payloadJson.toLowerCase().contains("secret")) {
            sensitiveData.add("Secret field detected");
        }
        if (payloadJson.toLowerCase().contains("apikey") || payloadJson.toLowerCase().contains("api_key")) {
            sensitiveData.add("API Key field detected");
        }
        if (payloadJson.toLowerCase().contains("token")) {
            sensitiveData.add("Token field detected");
        }
        
        if (!sensitiveData.isEmpty()) {
            addFinding("Sensitive Data in Token",
                      "Token contains potentially sensitive data: " + String.join(", ", sensitiveData) + 
                      " - JWTs are often logged/cached and should not contain PII",
                      Severity.HIGH);
        }
    }
    
    /**
     * 6. Check for header injection vulnerabilities
     */
    private void checkHeaderInjectionVulnerabilities() {
        JWTHeader header = token.getHeader();
        
        // Check kid (Key ID) parameter
        if (header.getKid() != null) {
            String kid = header.getKid();
            
            if (kid.contains("../") || kid.contains("..\\") || kid.contains("/etc") || kid.contains("C:\\")) {
                addFinding("Path Traversal in KID Parameter",
                          "KID: " + kid + " - Vulnerable to path traversal attacks to load arbitrary keys",
                          Severity.CRITICAL);
            }
            
            if (kid.contains(";") || kid.contains("|") || kid.contains("`") || 
                kid.contains("$") || kid.contains("&") || kid.contains("(")) {
                addFinding("Command Injection in KID Parameter",
                          "KID contains shell metacharacters - Possible command injection vulnerability",
                          Severity.CRITICAL);
            }
            
            if (kid.contains("'") || kid.contains("\"")) {
                addFinding("SQL Injection in KID Parameter",
                          "KID contains quotes - Possible SQL injection vulnerability",
                          Severity.HIGH);
            }
        }
        
        // Check jku (JWKS URL) parameter
        if (header.getJku() != null) {
            String jku = header.getJku();
            addFinding("Dynamic JKU URL Present",
                      "Token uses dynamic JWKS URL: " + jku + " - Vulnerable to SSRF and malicious key injection attacks",
                      Severity.CRITICAL);
            
            if (jku.toLowerCase().contains("http://")) {
                addFinding("JKU Over HTTP",
                          "JKU URL uses unencrypted HTTP - Vulnerable to MITM attacks",
                          Severity.HIGH);
            }
        }
        
        // Check x5u (X.509 URL) parameter
        if (header.getX5u() != null) {
            String x5u = header.getX5u();
            addFinding("Dynamic X5U URL Present",
                      "Token uses dynamic X.509 URL: " + x5u + " - Vulnerable to SSRF and certificate injection",
                      Severity.CRITICAL);
        }
    }
    
    /**
     * 7. Check token lifetime and expiration
     */
    private void checkTokenLifetime() {
        Long iat = token.getIssuedAt();
        Long exp = token.getExpiration();
        
        if (iat != null && exp != null) {
            long lifetime = exp - iat;
            long daysLifetime = lifetime / (24 * 60 * 60);
            
            if (lifetime > (30 * 24 * 60 * 60)) { // 30 days
                addFinding("Long Token Lifetime",
                          "Token lifetime is " + daysLifetime + " days - Significantly increases security risk",
                          Severity.HIGH);
            }
        }
        
        if (token.isExpired()) {
            addFinding("Token Expired",
                      "This token has already expired and should be rejected by servers",
                      Severity.LOW);
        }
    }
    
    /**
     * 8. Check replay attack vulnerability
     */
    private void checkReplayAttackVulnerability() {
        if (!token.hasClaim("jti")) {
            addFinding("Missing JWT ID (jti)",
                      "Token lacks unique identifier - Vulnerable to replay attacks. Cannot track or revoke specific tokens.",
                      Severity.MEDIUM);
        }
        
        if (!token.hasClaim("exp")) {
            addFinding("No Expiration - Critical Replay Risk",
                      "Token without expiration can be replayed indefinitely",
                      Severity.CRITICAL);
        }
    }
    
    /**
     * 9. Check for weak secret vulnerability
     */
    private void checkWeakSecrets() {
        String alg = token.getHeader().getAlg();
        if (alg != null && alg.startsWith("HS")) {
            addFinding("HMAC Algorithm - Brute Force Risk",
                      "Token uses HMAC - Vulnerable to secret brute force attacks if secret is weak (< 32 chars, dictionary words, etc)",
                      Severity.HIGH);
        }
    }
    
    /**
     * 10. Check timestamp validation issues
     */
    private void checkTimestampValidation() {
        // Check for invalid iat (issued at)
        if (token.hasClaim("iat")) {
            Object iat = token.getClaim("iat");
            if (iat instanceof Number) {
                long iatTime = ((Number) iat).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                
                if (iatTime < 0) {
                    addFinding("Invalid IAT Timestamp",
                              "Issued-at (iat) timestamp is negative - Invalid time value",
                              Severity.MEDIUM);
                }
                
                if (iatTime > currentTime + (60 * 60)) { // 1 hour in future
                    addFinding("IAT in Future",
                              "Issued-at (iat) timestamp is in the future - Token issued from unreliable clock",
                              Severity.MEDIUM);
                }
            }
        }
        
        // Check for nbf (not before) issues
        if (token.hasClaim("nbf")) {
            Object nbf = token.getClaim("nbf");
            if (nbf instanceof Number) {
                long nbfTime = ((Number) nbf).longValue();
                long currentTime = System.currentTimeMillis() / 1000;
                
                if (nbfTime > currentTime + (365 * 24 * 60 * 60)) {
                    addFinding("NBF in Distant Future",
                              "Not-before (nbf) timestamp is more than 1 year in future",
                              Severity.MEDIUM);
                }
                
                if (nbfTime > currentTime) {
                    addFinding("Token Not Yet Valid",
                              "Token 'not before' claim indicates it's not yet valid",
                              Severity.LOW);
                }
            }
        }
    }
    
    /**
     * 11. Check JWT ID validity
     */
    private void checkJTIValidity() {
        if (token.hasClaim("jti")) {
            Object jti = token.getClaim("jti");
            if (jti == null || jti.toString().isEmpty()) {
                addFinding("Empty JWT ID",
                          "JWT ID (jti) claim is empty - Cannot be used for token tracking/revocation",
                          Severity.MEDIUM);
            }
        }
    }
    
    /**
     * 12. Check header validation
     */
    private void checkHeaderValidation() {
        JWTHeader header = token.getHeader();
        
        if (header.getTyp() != null && !header.getTyp().equalsIgnoreCase("jwt")) {
            addFinding("Non-Standard Type Header",
                      "Type (typ) header is not 'JWT': " + header.getTyp(),
                      Severity.LOW);
        }
    }
    
    /**
     * Add a security finding
     */
    private void addFinding(String title, String description, Severity severity) {
        findings.add(new SecurityFinding(title, description, severity));
    }
    
    /**
     * Security Severity enum
     */
    public enum Severity {
        CRITICAL(4, "🔴"),
        HIGH(3, "🟠"),
        MEDIUM(2, "🟡"),
        LOW(1, "🟢"),
        INFO(0, "🔵");
        
        private final int level;
        private final String emoji;
        
        Severity(int level, String emoji) { 
            this.level = level;
            this.emoji = emoji;
        }
        
        public int getLevel() { return level; }
        public String getEmoji() { return emoji; }
    }
    
    /**
     * Security Finding class
     */
    public static class SecurityFinding implements Comparable<SecurityFinding> {
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
            return "[" + severity + "] " + title + "\n" + description;
        }
        
        @Override
        public int compareTo(SecurityFinding other) {
            return Integer.compare(other.severity.getLevel(), this.severity.getLevel());
        }
    }
}
