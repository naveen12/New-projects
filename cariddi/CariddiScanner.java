package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Core scanning engine for Cariddi
 */
public class CariddiScanner {
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private ExecutorService executorService;
    private volatile boolean isScanning = false;

    // Regex patterns for detection
    private static final Pattern AWS_KEY_PATTERN = Pattern.compile("AKIA[0-9A-Z]{16}");
    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile("-----BEGIN RSA PRIVATE KEY-----");
    private static final Pattern JWT_PATTERN = Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");
    private static final Pattern API_KEY_PATTERN = Pattern.compile("(?i)(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)[\\s:=]*['\"]?[A-Za-z0-9_-]{20,}['\"]?");
    private static final Pattern SLACK_TOKEN_PATTERN = Pattern.compile("xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9_-]{24,34}");
    private static final Pattern GITHUB_TOKEN_PATTERN = Pattern.compile("gh[pousr]_[A-Za-z0-9_]{36,255}");
    private static final Pattern STRIPE_KEY_PATTERN = Pattern.compile("sk_[a-z]{2}_(test|live)_[a-zA-Z0-9]{24}");
    private static final Pattern DATABASE_URL_PATTERN = Pattern.compile("(?i)(mongodb|mysql|postgresql|mongodb\\+srv)://[^\\s]+");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    private static final Pattern IP_PATTERN = Pattern.compile("\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b");

    // Common API endpoints
    private static final String[] COMMON_ENDPOINTS = {
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/rest/api",
        "/graphql",
        "/admin", "/admin/api",
        "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
        "/openapi", "/openapi.json",
        "/.well-known/openid-configuration",
        "/actuator", "/actuator/health",
        "/api-docs", "/api-docs.json",
        "/users", "/users/list", "/users/me",
        "/auth", "/auth/login", "/auth/register", "/oauth",
        "/config", "/settings", "/profile",
        "/debug", "/status", "/health",
        "/.git", "/.git/config",
        "/.env", "/env.php", "/config.php",
        "/robots.txt", "/sitemap.xml",
        "/backup", "/backups", "/upload", "/uploads"
    };

    // File extensions to scan for
    private static final Map<Integer, String[]> EXTENSION_LEVELS = new HashMap<>();

    static {
        // Level 1: Most juicy
        EXTENSION_LEVELS.put(1, new String[]{".key", ".pem", ".pfx", ".p12", ".env", ".config", ".conf", ".secret", ".credentials", ".password"});
        // Level 2: Very juicy
        EXTENSION_LEVELS.put(2, new String[]{".json", ".xml", ".yaml", ".yml", ".sql", ".db", ".bak", ".old", ".backup", ".log"});
        // Level 3: Juicy
        EXTENSION_LEVELS.put(3, new String[]{".txt", ".csv", ".xlsx", ".xls", ".doc", ".docx", ".zip", ".rar", ".tar", ".gz"});
        // Level 4: Medium
        EXTENSION_LEVELS.put(4, new String[]{".js", ".py", ".php", ".java", ".cs", ".rb", ".go", ".c", ".cpp", ".h"});
        // Level 5: Low-medium
        EXTENSION_LEVELS.put(5, new String[]{".html", ".css", ".scss", ".less", ".map", ".ts", ".tsx", ".jsx", ".vue"});
        // Level 6: Low
        EXTENSION_LEVELS.put(6, new String[]{".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf"});
        // Level 7: Not juicy
        EXTENSION_LEVELS.put(7, new String[]{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp"});
    }

    public CariddiScanner(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.stderr = stderr;
        this.executorService = Executors.newFixedThreadPool(20);
    }

    public void performScan(CariddiConfig config, CariddiScanProgressListener listener) {
        isScanning = true;
        new Thread(() -> {
            try {
                Set<String> discoveredUrls = ConcurrentHashMap.newKeySet();
                List<CariddiResult> allResults = new CopyOnWriteArrayList<>();
                int totalUrls = config.getUrls().length;

                listener.onStatusUpdate("Starting scan of " + totalUrls + " URL(s)");

                int urlIndex = 0;
                for (String urlStr : config.getUrls()) {
                    if (!isScanning) break;

                    urlIndex++;
                    int progress = (urlIndex * 100) / totalUrls;
                    listener.onProgress(progress);
                    listener.onStatusUpdate("Scanning: " + urlStr + " (" + urlIndex + "/" + totalUrls + ")");

                    try {
                        // Fetch the URL and analyze content
                        URL url = new URL(urlStr);
                        IHttpRequestResponse[] history = callbacks.getSiteMap(null);

                        // Scan the provided URL
                        scanUrlForFindings(urlStr, config, allResults, listener, discoveredUrls);

                        // Crawl for additional endpoints
                        if (config.isHuntEndpoints()) {
                            crawlForEndpoints(urlStr, config, allResults, listener, discoveredUrls);
                        }

                    } catch (Exception e) {
                        stderr.println("[!] Error scanning " + urlStr + ": " + e.getMessage());
                    }
                }

                listener.onProgress(100);
                listener.onStatusUpdate("Scan completed");
                listener.onComplete();
                isScanning = false;

            } catch (Exception e) {
                stderr.println("[!] Critical error during scan: " + e.getMessage());
                e.printStackTrace(stderr);
                isScanning = false;
            }
        }).start();
    }

    private void scanUrlForFindings(String urlStr, CariddiConfig config, List<CariddiResult> results, CariddiScanProgressListener listener, Set<String> discoveredUrls) {
        try {
            IHttpRequestResponse[] history = callbacks.getSiteMap(urlStr);
            
            for (IHttpRequestResponse entry : history) {
                if (!isScanning) break;

                String responseStr = new String(entry.getResponse());
                String requestStr = new String(entry.getRequest());

                // Hunt for secrets
                if (config.isHuntSecrets()) {
                    scanForSecrets(responseStr, urlStr, results, listener);
                    scanForSecrets(requestStr, urlStr, results, listener);
                }

                // Hunt for endpoints
                if (config.isHuntEndpoints()) {
                    scanForEndpoints(responseStr, urlStr, results, listener);
                    scanForEndpoints(requestStr, urlStr, results, listener);
                }

                // Hunt for errors
                if (config.isHuntErrors()) {
                    scanForErrors(responseStr, urlStr, results, listener);
                }

                // Hunt for info
                if (config.isHuntInfo()) {
                    scanForInfo(responseStr, urlStr, results, listener);
                }
            }
        } catch (Exception e) {
            stderr.println("[!] Error scanning URL: " + e.getMessage());
        }
    }

    private void crawlForEndpoints(String baseUrl, CariddiConfig config, List<CariddiResult> results, CariddiScanProgressListener listener, Set<String> discoveredUrls) {
        // Test common endpoints
        for (String endpoint : COMMON_ENDPOINTS) {
            if (!isScanning) break;

            String fullUrl = baseUrl.replaceAll("/$", "") + endpoint;
            
            if (discoveredUrls.add(fullUrl)) {
                try {
                    URL url = new URL(fullUrl);
                    java.net.URLConnection connection = url.openConnection();
                    
                    if (config.getCustomHeaders() != null && !config.getCustomHeaders().isEmpty()) {
                        // Parse and add custom headers
                        String[] headers = config.getCustomHeaders().split(";;");
                        for (String header : headers) {
                            String[] parts = header.split(":");
                            if (parts.length == 2) {
                                connection.setRequestProperty(parts[0].trim(), parts[1].trim());
                            }
                        }
                    }
                    
                    if (config.getUserAgent() != null && !config.getUserAgent().isEmpty()) {
                        connection.setRequestProperty("User-Agent", config.getUserAgent());
                    }

                    connection.setConnectTimeout(config.getTimeout() * 1000);
                    connection.setReadTimeout(config.getTimeout() * 1000);
                    
                    int responseCode = ((java.net.HttpURLConnection) connection).getResponseCode();
                    
                    if (responseCode < 400) {
                        CariddiResult result = new CariddiResult();
                        result.setType("Endpoint");
                        result.setUrl(fullUrl);
                        result.setFinding(endpoint);
                        result.setSeverity("Low");
                        result.setDetails("HTTP " + responseCode);
                        results.add(result);
                        listener.onResultFound(result);
                    }
                } catch (Exception e) {
                    // Endpoint doesn't exist
                }
            }
        }
    }

    private void scanForSecrets(String content, String url, List<CariddiResult> results, CariddiScanProgressListener listener) {
        // AWS keys
        Matcher awsMatcher = AWS_KEY_PATTERN.matcher(content);
        while (awsMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("AWS Access Key ID");
            result.setSeverity("High");
            result.setDetails(awsMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // JWT tokens
        Matcher jwtMatcher = JWT_PATTERN.matcher(content);
        while (jwtMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("JWT Token");
            result.setSeverity("High");
            result.setDetails(jwtMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // API Keys
        Matcher apiKeyMatcher = API_KEY_PATTERN.matcher(content);
        while (apiKeyMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("API Key");
            result.setSeverity("High");
            result.setDetails(apiKeyMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // Slack tokens
        Matcher slackMatcher = SLACK_TOKEN_PATTERN.matcher(content);
        while (slackMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("Slack Token");
            result.setSeverity("High");
            result.setDetails(slackMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // GitHub tokens
        Matcher githubMatcher = GITHUB_TOKEN_PATTERN.matcher(content);
        while (githubMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("GitHub Token");
            result.setSeverity("High");
            result.setDetails(githubMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // Stripe keys
        Matcher stripeMatcher = STRIPE_KEY_PATTERN.matcher(content);
        while (stripeMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("Stripe API Key");
            result.setSeverity("High");
            result.setDetails(stripeMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // Database URLs
        Matcher dbMatcher = DATABASE_URL_PATTERN.matcher(content);
        while (dbMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Secret");
            result.setUrl(url);
            result.setFinding("Database Connection String");
            result.setSeverity("High");
            result.setDetails(dbMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }
    }

    private void scanForEndpoints(String content, String url, List<CariddiResult> results, CariddiScanProgressListener listener) {
        // Find URLs in content
        Pattern urlPattern = Pattern.compile("(https?://[^\\s<>\"\\}]+)|([\\/][\\w\\-\\.]+)+");
        Matcher matcher = urlPattern.matcher(content);
        
        while (matcher.find() && isScanning) {
            String found = matcher.group();
            if (found.startsWith("/")) {
                CariddiResult result = new CariddiResult();
                result.setType("Endpoint");
                result.setUrl(url);
                result.setFinding(found);
                result.setSeverity("Low");
                result.setDetails("Discovered in response");
                results.add(result);
                listener.onResultFound(result);
            }
        }
    }

    private void scanForErrors(String content, String url, List<CariddiResult> results, CariddiScanProgressListener listener) {
        String[] errorPatterns = {
            "Exception", "Error", "Fatal", "Traceback",
            "at java.", "at com.", "at org.",
            "SQLException", "NullPointerException",
            "TypeError", "ReferenceError", "SyntaxError"
        };

        for (String pattern : errorPatterns) {
            if (content.contains(pattern)) {
                CariddiResult result = new CariddiResult();
                result.setType("Error");
                result.setUrl(url);
                result.setFinding("Error/Exception Disclosure");
                result.setSeverity("Medium");
                result.setDetails(pattern + " found in response");
                results.add(result);
                listener.onResultFound(result);
                break;
            }
        }
    }

    private void scanForInfo(String content, String url, List<CariddiResult> results, CariddiScanProgressListener listener) {
        // Emails
        Matcher emailMatcher = EMAIL_PATTERN.matcher(content);
        while (emailMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Info");
            result.setUrl(url);
            result.setFinding("Email Address");
            result.setSeverity("Low");
            result.setDetails(emailMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }

        // IP Addresses
        Matcher ipMatcher = IP_PATTERN.matcher(content);
        while (ipMatcher.find() && isScanning) {
            CariddiResult result = new CariddiResult();
            result.setType("Info");
            result.setUrl(url);
            result.setFinding("IP Address");
            result.setSeverity("Low");
            result.setDetails(ipMatcher.group());
            results.add(result);
            listener.onResultFound(result);
        }
    }

    public void stopScan() {
        isScanning = false;
    }
}

/**
 * Scan configuration
 */
class CariddiConfig {
    private String[] urls;
    private boolean huntEndpoints = true;
    private boolean huntSecrets = true;
    private boolean huntErrors = false;
    private boolean huntInfo = false;
    private boolean intensive = false;
    private int extensionLevel = 2;
    private int concurrency = 20;
    private int timeout = 10;
    private int maxDepth = 3;
    private String customHeaders = "";
    private String userAgent = "";

    // Getters and Setters
    public String[] getUrls() { return urls; }
    public void setUrls(String[] urls) { this.urls = urls; }

    public boolean isHuntEndpoints() { return huntEndpoints; }
    public void setHuntEndpoints(boolean v) { this.huntEndpoints = v; }

    public boolean isHuntSecrets() { return huntSecrets; }
    public void setHuntSecrets(boolean v) { this.huntSecrets = v; }

    public boolean isHuntErrors() { return huntErrors; }
    public void setHuntErrors(boolean v) { this.huntErrors = v; }

    public boolean isHuntInfo() { return huntInfo; }
    public void setHuntInfo(boolean v) { this.huntInfo = v; }

    public boolean isIntensive() { return intensive; }
    public void setIntensive(boolean v) { this.intensive = v; }

    public int getExtensionLevel() { return extensionLevel; }
    public void setExtensionLevel(int v) { this.extensionLevel = v; }

    public int getConcurrency() { return concurrency; }
    public void setConcurrency(int v) { this.concurrency = v; }

    public int getTimeout() { return timeout; }
    public void setTimeout(int v) { this.timeout = v; }

    public int getMaxDepth() { return maxDepth; }
    public void setMaxDepth(int v) { this.maxDepth = v; }

    public String getCustomHeaders() { return customHeaders; }
    public void setCustomHeaders(String v) { this.customHeaders = v; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String v) { this.userAgent = v; }
}

/**
 * Result object
 */
class CariddiResult {
    private String type;
    private String url;
    private String finding;
    private String severity;
    private String details;

    public String getType() { return type; }
    public void setType(String v) { this.type = v; }

    public String getUrl() { return url; }
    public void setUrl(String v) { this.url = v; }

    public String getFinding() { return finding; }
    public void setFinding(String v) { this.finding = v; }

    public String getSeverity() { return severity; }
    public void setSeverity(String v) { this.severity = v; }

    public String getDetails() { return details; }
    public void setDetails(String v) { this.details = v; }
}

/**
 * Progress listener interface
 */
interface CariddiScanProgressListener {
    void onProgress(int percent);
    void onResultFound(CariddiResult result);
    void onStatusUpdate(String message);
    void onComplete();
}


