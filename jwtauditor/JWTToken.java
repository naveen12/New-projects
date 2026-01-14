package burp.jwt;

import java.util.*;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Represents a parsed JWT Token with manipulation capabilities
 */
public class JWTToken {
    
    private JWTHeader header;
    private Map<String, Object> payload;
    private String signature;
    private String originalToken;
    
    public JWTToken(JWTHeader header, Map<String, Object> payload, String signature, String originalToken) {
        this.header = header;
        this.payload = new LinkedHashMap<>(payload);
        this.signature = signature != null ? signature : "";
        this.originalToken = originalToken;
    }
    
    /**
     * Reconstruct JWT token from header and payload
     */
    public String reconstructToken() {
        String headerJson = header.toJson();
        String payloadJson = JWTUtils.mapToJson(payload);
        
        String headerEncoded = JWTUtils.base64UrlEncode(headerJson);
        String payloadEncoded = JWTUtils.base64UrlEncode(payloadJson);
        
        return headerEncoded + "." + payloadEncoded + "." + signature;
    }
    
    /**
     * Get claim from payload
     */
    public Object getClaim(String claimName) {
        return payload.get(claimName);
    }
    
    /**
     * Set claim in payload
     */
    public void setClaim(String claimName, Object value) {
        payload.put(claimName, value);
    }
    
    /**
     * Remove claim from payload
     */
    public void removeClaim(String claimName) {
        payload.remove(claimName);
    }
    
    /**
     * Check if token has claim
     */
    public boolean hasClaim(String claimName) {
        return payload.containsKey(claimName);
    }
    
    /**
     * Get all claims
     */
    public Set<String> getAllClaims() {
        return payload.keySet();
    }
    
    /**
     * Get expiration time (Unix timestamp)
     */
    public Long getExpiration() {
        Object exp = payload.get("exp");
        if (exp instanceof Number) {
            return ((Number) exp).longValue();
        }
        return null;
    }
    
    /**
     * Get expiration as formatted date
     */
    public String getExpirationDate() {
        Long exp = getExpiration();
        if (exp != null) {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(exp * 1000));
        }
        return "Never";
    }
    
    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        Long exp = getExpiration();
        if (exp == null) {
            return false; // No expiration = not expired
        }
        long currentTime = System.currentTimeMillis() / 1000;
        return currentTime > exp;
    }
    
    /**
     * Get issued at time (Unix timestamp)
     */
    public Long getIssuedAt() {
        Object iat = payload.get("iat");
        if (iat instanceof Number) {
            return ((Number) iat).longValue();
        }
        return null;
    }
    
    /**
     * Get not-before time (Unix timestamp)
     */
    public Long getNotBefore() {
        Object nbf = payload.get("nbf");
        if (nbf instanceof Number) {
            return ((Number) nbf).longValue();
        }
        return null;
    }
    
    /**
     * Get subject claim
     */
    public String getSubject() {
        Object sub = payload.get("sub");
        return sub != null ? sub.toString() : null;
    }
    
    /**
     * Get issuer claim
     */
    public String getIssuer() {
        Object iss = payload.get("iss");
        return iss != null ? iss.toString() : null;
    }
    
    /**
     * Get audience claim
     */
    public String getAudience() {
        Object aud = payload.get("aud");
        return aud != null ? aud.toString() : null;
    }
    
    /**
     * Get JWT ID claim
     */
    public String getJTI() {
        Object jti = payload.get("jti");
        return jti != null ? jti.toString() : null;
    }
    
    /**
     * Check if it's a valid token structure
     */
    public boolean isValid() {
        return header != null && !payload.isEmpty() && header.getAlg() != null;
    }
    
    /**
     * Get token size in bytes
     */
    public int getTokenSize() {
        return originalToken.getBytes().length;
    }
    
    /**
     * Get payload size
     */
    public int getPayloadSize() {
        return JWTUtils.mapToJson(payload).getBytes().length;
    }
    
    /**
     * Pretty print token information
     */
    public String getTokenInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== JWT Token Information ===\n");
        sb.append("Algorithm: ").append(header.getAlg()).append("\n");
        sb.append("Subject: ").append(getSubject()).append("\n");
        sb.append("Issuer: ").append(getIssuer()).append("\n");
        sb.append("Audience: ").append(getAudience()).append("\n");
        sb.append("Issued At: ").append(getIssuedAt()).append("\n");
        sb.append("Expires: ").append(getExpirationDate()).append("\n");
        sb.append("Expired: ").append(isExpired()).append("\n");
        sb.append("Token Size: ").append(getTokenSize()).append(" bytes\n");
        sb.append("Claims: ").append(payload.size()).append("\n");
        return sb.toString();
    }
    
    /**
     * Get payload as JSON string
     */
    public String getPayloadJson() {
        return JWTUtils.mapToJson(payload);
    }
    
    // Getters and setters
    public JWTHeader getHeader() { return header; }
    public void setHeader(JWTHeader header) { this.header = header; }
    
    public Map<String, Object> getPayload() { return payload; }
    public void setPayload(Map<String, Object> payload) { this.payload = payload; }
    
    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }
    
    public String getOriginalToken() { return originalToken; }
    public void setOriginalToken(String originalToken) { this.originalToken = originalToken; }
}
