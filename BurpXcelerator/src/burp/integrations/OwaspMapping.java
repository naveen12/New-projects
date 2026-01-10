package burp.integrations;

import java.util.HashMap;
import java.util.Map;

public class OwaspMapping {
    private static final Map<String, String> owaspMap = new HashMap<>();

    static {
        // Example mappings
        owaspMap.put("SQL Injection", "A03:2021-Injection");
        owaspMap.put("Cross-Site Scripting (XSS)", "A03:2021-Injection");
        owaspMap.put("Broken Authentication", "A07:2021-Identification and Authentication Failures");
        owaspMap.put("Broken Access Control", "A01:2021-Broken Access Control");
        owaspMap.put("Security Misconfiguration", "A05:2021-Security Misconfiguration");
        owaspMap.put("Insecure Deserialization", "A08:2021-Software and Data Integrity Failures");
        owaspMap.put("Sensitive Data Exposure", "A02:2021-Cryptographic Failures");
        owaspMap.put("XML External Entities (XXE)", "A05:2021-Security Misconfiguration");
        owaspMap.put("Using Components with Known Vulnerabilities", "A06:2021-Vulnerable and Outdated Components");
        owaspMap.put("Insufficient Logging & Monitoring", "A09:2021-Security Logging and Monitoring Failures");
        owaspMap.put("Server-Side Request Forgery (SSRF)", "A10:2021-Server-Side Request Forgery (SSRF)");
    }

    public static String getOwaspTop10Category(String vulnerabilityName) {
        return owaspMap.getOrDefault(vulnerabilityName, "Uncategorized");
    }
}
