package burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;
import burp.ui.MainUI;

import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * CoreEngine: The core module that captures all HTTP traffic from Burp's Proxy,
 * normalizes request/response data, stores it in thread-safe structures, and provides
 * a reusable risk scoring engine (0-10 scale).
 */
public class CoreEngine implements IHttpListener {
    private final IBurpExtenderCallbacks callbacks;
    private MainUI mainUI;
    
    // Thread-safe storage for all captured traffic
    private final ConcurrentHashMap<String, HttpTransaction> urlToTransaction;
    private final ConcurrentHashMap<IHttpRequestResponse, RequestMetadata> requestMetadata;
    private final ExecutorService executorService;
    
    // Static resources to ignore
    private static final Set<String> STATIC_EXTENSIONS = new HashSet<>(Arrays.asList(
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", 
            ".ttf", ".eot", ".ico", ".xml", ".json", ".pdf", ".mp4", ".webm", ".webp"
    ));
    
    // Keywords that indicate potentially attackable URLs
    private static final Set<String> ATTACK_KEYWORDS = new HashSet<>(Arrays.asList(
            "api", "admin", "user", "account", "profile", "config", "settings", "debug",
            "test", "auth", "login", "register", "data", "report", "export", "import"
    ));
    
    public CoreEngine(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.urlToTransaction = new ConcurrentHashMap<>();
        this.requestMetadata = new ConcurrentHashMap<>();
        this.executorService = Executors.newFixedThreadPool(10);
    }
    
    public void setMainUI(MainUI mainUI) {
        this.mainUI = mainUI;
    }

    /**
     * Processes all HTTP messages from the Proxy tool.
     * Captures traffic, normalizes data, and scores URLs for relevance.
     */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process Proxy traffic
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }
        
        // Process responses
        if (!messageIsRequest) {
            executorService.submit(() -> {
                try {
                    processResponse(messageInfo);
                } catch (Exception e) {
                    callbacks.printError("Error processing HTTP message: " + e.getMessage());
                }
            });
        }
    }
    
    /**
     * Process a captured response: normalize data, score relevance, extract parameters.
     */
    private void processResponse(IHttpRequestResponse messageInfo) {
        try {
            IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
            IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
            
            URL url = requestInfo.getUrl();
            String urlString = url.toString();
            
            // Ignore static resources
            if (isStaticResource(urlString)) {
                return;
            }
            
            // Calculate URL relevance score (0-10)
            int urlScore = calculateURLScore(requestInfo, responseInfo);
            
            // Create transaction object
            HttpTransaction transaction = new HttpTransaction(
                    urlString,
                    requestInfo.getMethod(),
                    responseInfo.getStatusCode(),
                    requestInfo,
                    responseInfo,
                    messageInfo
            );
            
            // Store transaction
            urlToTransaction.put(urlString, transaction);
            RequestMetadata metadata = new RequestMetadata(urlString, urlScore, requestInfo, responseInfo);
            requestMetadata.put(messageInfo, metadata);
            
            // Update UI
            if (mainUI != null) {
                mainUI.getURLRelevanceUI().addURL(transaction);
                
                // Analyze parameters
                analyzeAndStoreParameters(requestInfo, urlScore);
            }
        } catch (Exception e) {
            callbacks.printError("Error in processResponse: " + e.getMessage());
        }
    }
    
    /**
     * Analyze and store parameters with risk classification.
     */
    private void analyzeAndStoreParameters(IRequestInfo requestInfo, int urlScore) {
        if (mainUI == null) return;
        
        List<burp.IParameter> parameters = requestInfo.getParameters();
        for (burp.IParameter param : parameters) {
            String name = param.getName();
            String value = param.getValue();
            int type = param.getType();
            
            String paramType = classifyParameter(name, value);
            int paramRisk = calculateParameterRisk(paramType, urlScore);
            
            // Create and add parameter
            burp.parameters.Parameter parameter = new burp.parameters.Parameter(
                    name, value, paramType, paramRisk
            );
            mainUI.getParameterAnalyzerUI().addParameter(parameter);
        }
    }
    
    /**
     * Calculate URL relevance score (0-10 scale).
     * Considers HTTP method, keywords in URL, parameters, and response status.
     */
    public int calculateURLScore(IRequestInfo requestInfo, IResponseInfo responseInfo) {
        int score = 0;
        String method = requestInfo.getMethod();
        URL url = requestInfo.getUrl();
        String urlString = url.toString().toLowerCase();
        
        // HTTP method scoring: modifying methods are riskier
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT")) {
            score += 3;
        } else if (method.equalsIgnoreCase("DELETE")) {
            score += 4;
        } else if (method.equalsIgnoreCase("GET") || method.equalsIgnoreCase("HEAD")) {
            score += 1;
        }
        
        // Keyword-based scoring: API and sensitive endpoints
        for (String keyword : ATTACK_KEYWORDS) {
            if (urlString.contains(keyword)) {
                score += 2;
            }
        }
        
        // Parameter presence scoring
        List<burp.IParameter> params = requestInfo.getParameters();
        if (!params.isEmpty()) {
            score += Math.min(params.size(), 3); // Max +3 for parameters
        }
        
        // Response status scoring: 2xx/3xx are normal, 4xx/5xx might indicate issues
        int statusCode = responseInfo.getStatusCode();
        if (statusCode >= 400) {
            score += 1; // Potential error condition to investigate
        }
        
        // URL path depth scoring: deeper paths often have more endpoints
        String path = url.getPath();
        if (path != null) {
            int slashCount = (int) path.chars().filter(ch -> ch == '/').count();
            if (slashCount > 3) {
                score += 1;
            }
        }
        
        // Normalize to 0-10 scale
        return Math.min(score, 10);
    }
    
    /**
     * Classify a parameter based on its name and value patterns.
     */
    private String classifyParameter(String name, String value) {
        String nameLower = name.toLowerCase();
        
        // ID-like pattern detection
        if (nameLower.contains("id") || nameLower.endsWith("_id") || 
            nameLower.endsWith("id") || nameLower.startsWith("id_")) {
            if (value.matches("\\d+")) {
                return "Numeric ID";
            } else {
                return "String ID";
            }
        }
        
        // User/account related
        if (nameLower.contains("user") || nameLower.contains("account") || 
            nameLower.contains("member") || nameLower.contains("owner")) {
            return "User Reference";
        }
        
        // Token/auth related
        if (nameLower.contains("token") || nameLower.contains("auth") || 
            nameLower.contains("api_key") || nameLower.contains("secret")) {
            return "Authentication";
        }
        
        // Numeric classification
        if (value.matches("\\d+")) {
            return "Numeric";
        }
        
        // Boolean-like
        if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false") ||
            value.equals("0") || value.equals("1")) {
            return "Boolean";
        }
        
        // Default to string
        return "String";
    }
    
    /**
     * Calculate parameter risk score considering parameter type and URL score.
     */
    private int calculateParameterRisk(String paramType, int urlScore) {
        int baseRisk = 0;
        
        switch (paramType) {
            case "Numeric ID":
            case "String ID":
                baseRisk = 8;
                break;
            case "User Reference":
                baseRisk = 7;
                break;
            case "Authentication":
                baseRisk = 9;
                break;
            case "Numeric":
                baseRisk = 5;
                break;
            case "Boolean":
                baseRisk = 4;
                break;
            case "String":
            default:
                baseRisk = 3;
                break;
        }
        
        // Factor in URL score
        int adjustedRisk = (baseRisk + (urlScore / 3)) / 2;
        return Math.min(adjustedRisk, 10);
    }
    
    /**
     * Check if a URL is a static resource that should be ignored.
     */
    private boolean isStaticResource(String url) {
        String urlLower = url.toLowerCase();
        for (String extension : STATIC_EXTENSIONS) {
            if (urlLower.endsWith(extension)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get all captured transactions.
     */
    public Collection<HttpTransaction> getAllTransactions() {
        return new ArrayList<>(urlToTransaction.values());
    }
    
    /**
     * Get transaction by URL.
     */
    public HttpTransaction getTransaction(String url) {
        return urlToTransaction.get(url);
    }
    
    /**
     * Get metadata for a request.
     */
    public RequestMetadata getRequestMetadata(IHttpRequestResponse messageInfo) {
        return requestMetadata.get(messageInfo);
    }
    
    /**
     * Shutdown the executor service gracefully.
     */
    public void shutdown() {
        executorService.shutdownNow();
    }
    
    /**
     * Represents a captured HTTP transaction with all relevant data.
     */
    public static class HttpTransaction {
        public final String url;
        public final String method;
        public final int statusCode;
        public final IRequestInfo requestInfo;
        public final IResponseInfo responseInfo;
        public final IHttpRequestResponse messageInfo;
        public final long timestamp;
        
        public HttpTransaction(String url, String method, int statusCode,
                             IRequestInfo requestInfo, IResponseInfo responseInfo,
                             IHttpRequestResponse messageInfo) {
            this.url = url;
            this.method = method;
            this.statusCode = statusCode;
            this.requestInfo = requestInfo;
            this.responseInfo = responseInfo;
            this.messageInfo = messageInfo;
            this.timestamp = System.currentTimeMillis();
        }
    }
    
    /**
     * Metadata for a captured request.
     */
    public static class RequestMetadata {
        public final String url;
        public final int relevanceScore;
        public final IRequestInfo requestInfo;
        public final IResponseInfo responseInfo;
        public final long timestamp;
        
        public RequestMetadata(String url, int relevanceScore, 
                             IRequestInfo requestInfo, IResponseInfo responseInfo) {
            this.url = url;
            this.relevanceScore = relevanceScore;
            this.requestInfo = requestInfo;
            this.responseInfo = responseInfo;
            this.timestamp = System.currentTimeMillis();
        }
    }
}
