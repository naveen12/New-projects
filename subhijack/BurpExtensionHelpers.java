package burp.subhijack;

/**
 * Helper utility class for Burp Suite integration
 * Provides URL processing and network utilities
 */
public class BurpExtensionHelpers {
    
    // Placeholder for callbacks - would be set by Burp framework
    private static Object callbacks;
    private static Object helpers;
    
    public static void setCallbacks(Object callbacks) {
        BurpExtensionHelpers.callbacks = callbacks;
        BurpExtensionHelpers.helpers = callbacks;
    }
    
    public static Object getCallbacks() {
        return callbacks;
    }
    
    public static Object getHelpers() {
        return helpers;
    }
    
    public static String extractDomain(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url);
            String host = urlObj.getHost();
            if (host != null && !host.isEmpty()) {
                return host;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return url;
    }
    
    public static boolean isValidUrl(String url) {
        try {
            new java.net.URL(url);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    public static String normalizeUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return "https://" + url;
        }
        return url;
    }
}
