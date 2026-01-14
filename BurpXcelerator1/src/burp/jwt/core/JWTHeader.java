package burp.jwt.core;

import java.util.*;

/**
 * Represents a JWT Header
 */
public class JWTHeader {
    
    private String alg;           // Algorithm
    private String typ;           // Type
    private String kid;           // Key ID
    private String jku;           // JWKS URL
    private String x5u;           // X.509 URL
    private String x5t;           // X.509 Thumbprint
    private String cty;           // Content Type
    private String crit;          // Critical
    private Map<String, Object> customFields;
    
    public JWTHeader() {
        this.customFields = new LinkedHashMap<>();
    }
    
    public static JWTHeader fromJson(String json) throws Exception {
        JWTHeader header = new JWTHeader();
        Map<String, Object> map = JWTUtils.parseJson(json);
        
        header.alg = (String) map.get("alg");
        header.typ = (String) map.get("typ");
        header.kid = (String) map.get("kid");
        header.jku = (String) map.get("jku");
        header.x5u = (String) map.get("x5u");
        header.x5t = (String) map.get("x5t");
        header.cty = (String) map.get("cty");
        header.crit = (String) map.get("crit");
        
        // Store custom fields
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!isStandardField(entry.getKey())) {
                header.customFields.put(entry.getKey(), entry.getValue());
            }
        }
        
        return header;
    }
    
    private static boolean isStandardField(String fieldName) {
        return fieldName.equals("alg") || fieldName.equals("typ") || 
               fieldName.equals("kid") || fieldName.equals("jku") || 
               fieldName.equals("x5u") || fieldName.equals("x5t") || 
               fieldName.equals("cty") || fieldName.equals("crit");
    }
    
    public String toJson() {
        Map<String, Object> map = new LinkedHashMap<>();
        
        if (alg != null) map.put("alg", alg);
        if (typ != null) map.put("typ", typ);
        if (kid != null) map.put("kid", kid);
        if (jku != null) map.put("jku", jku);
        if (x5u != null) map.put("x5u", x5u);
        if (x5t != null) map.put("x5t", x5t);
        if (cty != null) map.put("cty", cty);
        if (crit != null) map.put("crit", crit);
        
        // Add custom fields
        map.putAll(customFields);
        
        return JWTUtils.mapToJson(map);
    }
    
    // Getters and setters
    public String getAlg() { return alg; }
    public void setAlg(String alg) { this.alg = alg; }
    
    public String getTyp() { return typ; }
    public void setTyp(String typ) { this.typ = typ; }
    
    public String getKid() { return kid; }
    public void setKid(String kid) { this.kid = kid; }
    
    public String getJku() { return jku; }
    public void setJku(String jku) { this.jku = jku; }
    
    public String getX5u() { return x5u; }
    public void setX5u(String x5u) { this.x5u = x5u; }
    
    public String getX5t() { return x5t; }
    public void setX5t(String x5t) { this.x5t = x5t; }
    
    public String getCty() { return cty; }
    public void setCty(String cty) { this.cty = cty; }
    
    public String getCrit() { return crit; }
    public void setCrit(String crit) { this.crit = crit; }
    
    public Map<String, Object> getCustomFields() { return customFields; }
}
