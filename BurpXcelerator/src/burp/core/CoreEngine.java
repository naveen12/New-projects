package burp.core;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

import burp.IRequestInfo;
import burp.ui.MainUI;

import java.net.URL;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class CoreEngine implements IHttpListener {
    private final IBurpExtenderCallbacks callbacks;
    private final MainUI mainUI;
    private final ConcurrentHashMap<IHttpRequestResponse, Integer> requestResponseMap;
    private final ExecutorService executorService;

    public CoreEngine(IBurpExtenderCallbacks callbacks, MainUI mainUI) {
        this.callbacks = callbacks;
        this.mainUI = mainUI;
        this.requestResponseMap = new ConcurrentHashMap<>();
        this.executorService = Executors.newFixedThreadPool(10);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
            if (!messageIsRequest) {
                executorService.submit(() -> {
                    IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
                    URL url = requestInfo.getUrl();
                    int score = calculateURLScore(requestInfo);
                    requestResponseMap.put(messageInfo, score);
                    mainUI.getURLRelevanceUI().addURL(url.toString(), score);
                    analyzeParameters(requestInfo);
                });
            }
        }
    }

    private void analyzeParameters(IRequestInfo requestInfo) {
        for (burp.IParameter parameter : requestInfo.getParameters()) {
            String name = parameter.getName();
            String value = parameter.getValue();
            String type = classifyParameter(name, value);
            int riskScore = calculateParameterRisk(type);
            mainUI.getParameterAnalyzerUI().addParameter(new burp.parameters.Parameter(name, value, type, riskScore));
        }
    }

    private String classifyParameter(String name, String value) {
        if (name.toLowerCase().contains("id") || name.toLowerCase().endsWith("_id")) {
            return "ID-like";
        }
        if (value.matches("\\d+")) {
            return "Numeric";
        }
        return "String";
    }

    private int calculateParameterRisk(String type) {
        switch (type) {
            case "ID-like":
                return 8;
            case "Numeric":
                return 5;
            case "String":
            default:
                return 3;
        }
    }

    private int calculateURLScore(IRequestInfo requestInfo) {
        int score = 0;
        String method = requestInfo.getMethod();
        URL url = requestInfo.getUrl();
        String urlString = url.toString();

        // Score based on HTTP method
        if (method.equalsIgnoreCase("POST") || method.equalsIgnoreCase("PUT") || method.equalsIgnoreCase("DELETE")) {
            score += 2;
        }

        // Score based on keywords in URL
        String[] keywords = {"api", "admin", "user", "account", "config", "debug", "test"};
        for (String keyword : keywords) {
            if (urlString.contains(keyword)) {
                score += 3;
            }
        }

        // Score based on parameters
        if (!requestInfo.getParameters().isEmpty()) {
            score += 1;
        }
        
        // Ignore static resources
        if (isStaticResource(urlString)) {
            return 0;
        }

        return Math.min(score, 10);
    }
    
    private boolean isStaticResource(String url) {
        String[] extensions = {".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".eot"};
        for (String ext : extensions) {
            if (url.toLowerCase().endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    public ConcurrentHashMap<IHttpRequestResponse, Integer> getRequestResponseMap() {
        return requestResponseMap;
    }

    public int getRiskScore(IHttpRequestResponse messageInfo) {
        return requestResponseMap.getOrDefault(messageInfo, 0);
    }
}
