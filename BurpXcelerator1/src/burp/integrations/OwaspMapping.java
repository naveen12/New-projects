package burp.integrations;

import java.util.*;

/**
 * OwaspMapping: Maps vulnerabilities and findings to OWASP Top 10 2021 categories.
 * Provides easy classification of security issues discovered by various tools.
 */
public class OwaspMapping {
    
    // OWASP Top 10 2021 Categories
    private static final Map<String, String> VULNERABILITY_MAPPING = new HashMap<>();
    
    static {
        // A01:2021 - Broken Access Control
        VULNERABILITY_MAPPING.put("broken access control", "A01:2021-Broken Access Control");
        VULNERABILITY_MAPPING.put("missing access control", "A01:2021-Broken Access Control");
        VULNERABILITY_MAPPING.put("privilege escalation", "A01:2021-Broken Access Control");
        VULNERABILITY_MAPPING.put("insecure direct object reference", "A01:2021-Broken Access Control");
        VULNERABILITY_MAPPING.put("idor", "A01:2021-Broken Access Control");
        
        // A02:2021 - Cryptographic Failures
        VULNERABILITY_MAPPING.put("sensitive data exposure", "A02:2021-Cryptographic Failures");
        VULNERABILITY_MAPPING.put("weak encryption", "A02:2021-Cryptographic Failures");
        VULNERABILITY_MAPPING.put("ssl/tls", "A02:2021-Cryptographic Failures");
        VULNERABILITY_MAPPING.put("insecure cryptographic", "A02:2021-Cryptographic Failures");
        
        // A03:2021 - Injection
        VULNERABILITY_MAPPING.put("sql injection", "A03:2021-Injection");
        VULNERABILITY_MAPPING.put("cross-site scripting", "A03:2021-Injection");
        VULNERABILITY_MAPPING.put("xss", "A03:2021-Injection");
        VULNERABILITY_MAPPING.put("command injection", "A03:2021-Injection");
        VULNERABILITY_MAPPING.put("ldap injection", "A03:2021-Injection");
        VULNERABILITY_MAPPING.put("os command injection", "A03:2021-Injection");
        
        // A04:2021 - Insecure Design
        VULNERABILITY_MAPPING.put("insecure design", "A04:2021-Insecure Design");
        VULNERABILITY_MAPPING.put("broken business logic", "A04:2021-Insecure Design");
        
        // A05:2021 - Security Misconfiguration
        VULNERABILITY_MAPPING.put("security misconfiguration", "A05:2021-Security Misconfiguration");
        VULNERABILITY_MAPPING.put("debug enabled", "A05:2021-Security Misconfiguration");
        VULNERABILITY_MAPPING.put("default credentials", "A05:2021-Security Misconfiguration");
        VULNERABILITY_MAPPING.put("xxe", "A05:2021-Security Misconfiguration");
        VULNERABILITY_MAPPING.put("xml external entities", "A05:2021-Security Misconfiguration");
        
        // A06:2021 - Vulnerable and Outdated Components
        VULNERABILITY_MAPPING.put("vulnerable component", "A06:2021-Vulnerable and Outdated Components");
        VULNERABILITY_MAPPING.put("outdated library", "A06:2021-Vulnerable and Outdated Components");
        VULNERABILITY_MAPPING.put("known vulnerability", "A06:2021-Vulnerable and Outdated Components");
        
        // A07:2021 - Authentication and Session Management Failures
        VULNERABILITY_MAPPING.put("broken authentication", "A07:2021-Authentication and Session Management Failures");
        VULNERABILITY_MAPPING.put("session fixation", "A07:2021-Authentication and Session Management Failures");
        VULNERABILITY_MAPPING.put("weak password", "A07:2021-Authentication and Session Management Failures");
        VULNERABILITY_MAPPING.put("authentication bypass", "A07:2021-Authentication and Session Management Failures");
        
        // A08:2021 - Software and Data Integrity Failures
        VULNERABILITY_MAPPING.put("insecure deserialization", "A08:2021-Software and Data Integrity Failures");
        VULNERABILITY_MAPPING.put("insecure update", "A08:2021-Software and Data Integrity Failures");
        VULNERABILITY_MAPPING.put("integrity failure", "A08:2021-Software and Data Integrity Failures");
        
        // A09:2021 - Logging and Monitoring Failures
        VULNERABILITY_MAPPING.put("insufficient logging", "A09:2021-Logging and Monitoring Failures");
        VULNERABILITY_MAPPING.put("missing monitoring", "A09:2021-Logging and Monitoring Failures");
        
        // A10:2021 - Server-Side Request Forgery (SSRF)
        VULNERABILITY_MAPPING.put("ssrf", "A10:2021-Server-Side Request Forgery");
        VULNERABILITY_MAPPING.put("server-side request forgery", "A10:2021-Server-Side Request Forgery");
    }
    
    /**
     * Map a vulnerability name to OWASP Top 10 category.
     */
    public static String getOwaspCategory(String vulnerabilityName) {
        if (vulnerabilityName == null || vulnerabilityName.isEmpty()) {
            return "Uncategorized";
        }
        
        String nameLower = vulnerabilityName.toLowerCase();
        for (Map.Entry<String, String> entry : VULNERABILITY_MAPPING.entrySet()) {
            if (nameLower.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        
        return "Uncategorized";
    }
    
    /**
     * Get all OWASP categories.
     */
    public static Collection<String> getAllCategories() {
        Set<String> categories = new HashSet<>();
        for (String category : VULNERABILITY_MAPPING.values()) {
            categories.add(category);
        }
        return categories;
    }
    
    /**
     * Get all vulnerabilities for a category.
     */
    public static List<String> getVulnerabilitiesForCategory(String category) {
        List<String> vulns = new ArrayList<>();
        for (Map.Entry<String, String> entry : VULNERABILITY_MAPPING.entrySet()) {
            if (entry.getValue().equals(category)) {
                vulns.add(entry.getKey());
            }
        }
        return vulns;
    }
}
