package burp.jwt.core;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Core JWT utilities for encoding/decoding and parsing
 */
public class JWTUtils {
    
    private static final Pattern JWT_PATTERN = Pattern.compile("^([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)$");
    
    /**
     * Base64URL decode
     */
    public static String base64UrlDecode(String input) {
        String base64 = input.replace('-', '+').replace('_', '/');
        
        int padding = 4 - (base64.length() % 4);
        if (padding != 4) {
            base64 += "=".repeat(padding);
        }
        
        byte[] decoded = Base64.getDecoder().decode(base64);
        return new String(decoded, StandardCharsets.UTF_8);
    }
    
    /**
     * Base64URL encode
     */
    public static String base64UrlEncode(String input) {
        byte[] bytes = input.getBytes(StandardCharsets.UTF_8);
        return base64UrlEncode(bytes);
    }
    
    /**
     * Base64URL encode bytes
     */
    public static String base64UrlEncode(byte[] input) {
        String base64 = Base64.getEncoder().encodeToString(input);
        return base64.replace('+', '-').replace('/', '_').replaceAll("=+$", "");
    }
    
    /**
     * Validate JWT format
     */
    public static boolean isValidJWT(String token) {
        if (token == null || token.trim().isEmpty()) {
            return false;
        }
        
        token = token.trim();
        
        // Check for URL patterns
        if (token.startsWith("http") || token.contains("://") || token.contains("www.")) {
            return false;
        }
        
        return JWT_PATTERN.matcher(token).matches();
    }
    
    /**
     * Parse JWT token
     */
    public static JWTToken parseToken(String token) throws Exception {
        if (!isValidJWT(token)) {
            throw new IllegalArgumentException("Invalid JWT format");
        }
        
        String[] parts = token.split("\\.");
        
        if (parts.length < 2 || parts.length > 3) {
            throw new IllegalArgumentException("JWT must have 2 or 3 parts");
        }
        
        // Decode header and payload
        String headerJson = base64UrlDecode(parts[0]);
        String payloadJson = base64UrlDecode(parts[1]);
        String signature = parts.length == 3 ? parts[2] : "";
        
        // Parse JSON
        JWTHeader header = JWTHeader.fromJson(headerJson);
        Map<String, Object> payload = parseJson(payloadJson);
        
        return new JWTToken(header, payload, signature, token);
    }
    
    /**
     * Parse JSON string
     */
    public static Map<String, Object> parseJson(String json) throws Exception {
        // Simple JSON parsing - in production use Jackson or similar
        Map<String, Object> map = new LinkedHashMap<>();
        
        // Remove outer braces
        json = json.trim();
        if (json.startsWith("{") && json.endsWith("}")) {
            json = json.substring(1, json.length() - 1);
        } else {
            throw new IllegalArgumentException("Invalid JSON format");
        }
        
        if (json.isEmpty()) {
            return map;
        }
        
        // Simple split by comma (this is basic - use proper JSON parser in production)
        String[] pairs = json.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
        
        for (String pair : pairs) {
            int colonIndex = pair.indexOf(":");
            if (colonIndex > 0) {
                String key = pair.substring(0, colonIndex).trim().replaceAll("^\"|\"$", "");
                String value = pair.substring(colonIndex + 1).trim();
                
                // Parse value type
                if (value.equals("null")) {
                    map.put(key, null);
                } else if (value.equals("true")) {
                    map.put(key, true);
                } else if (value.equals("false")) {
                    map.put(key, false);
                } else if (value.startsWith("\"") && value.endsWith("\"")) {
                    map.put(key, value.substring(1, value.length() - 1));
                } else {
                    try {
                        if (value.contains(".")) {
                            map.put(key, Double.parseDouble(value));
                        } else {
                            map.put(key, Long.parseLong(value));
                        }
                    } catch (NumberFormatException e) {
                        map.put(key, value);
                    }
                }
            }
        }
        
        return map;
    }
    
    /**
     * Convert map to JSON string
     */
    public static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            
            sb.append("\"").append(entry.getKey()).append("\":");
            Object value = entry.getValue();
            
            if (value == null) {
                sb.append("null");
            } else if (value instanceof String) {
                sb.append("\"").append(escapeJson((String) value)).append("\"");
            } else if (value instanceof Boolean || value instanceof Number) {
                sb.append(value);
            } else {
                sb.append("\"").append(value.toString()).append("\"");
            }
        }
        
        sb.append("}");
        return sb.toString();
    }
    
    /**
     * Escape JSON string
     */
    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
