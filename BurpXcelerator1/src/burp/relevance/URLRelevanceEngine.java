package burp.relevance;

import burp.core.CoreEngine;

import java.util.*;
import java.util.stream.Collectors;

/**
 * URLRelevanceEngine: Manages URL scoring and filtering based on relevance.
 * Ignores static resources and scores URLs based on HTTP methods, keywords, and parameters.
 */
public class URLRelevanceEngine {
    public final Map<String, URLData> urlDataMap;
    private boolean showOnlyAttackableURLs;
    
    public URLRelevanceEngine() {
        this.urlDataMap = new LinkedHashMap<>();
        this.showOnlyAttackableURLs = false;
    }
    
    /**
     * Add or update URL data with relevance score.
     */
    public void addURL(String url, int score) {
        urlDataMap.put(url, new URLData(url, score));
    }
    
    /**
     * Get all URLs, optionally filtered.
     */
    public List<URLData> getURLs(boolean filterAttackable) {
        return urlDataMap.values().stream()
                .filter(u -> !filterAttackable || u.score >= 5)
                .collect(Collectors.toList());
    }
    
    /**
     * Set the filter mode.
     */
    public void setShowOnlyAttackableURLs(boolean show) {
        this.showOnlyAttackableURLs = show;
    }
    
    /**
     * Get the current filter mode.
     */
    public boolean isShowOnlyAttackableURLs() {
        return showOnlyAttackableURLs;
    }
    
    /**
     * Get URL data by URL string.
     */
    public URLData getURLData(String url) {
        return urlDataMap.get(url);
    }
    
    /**
     * Data class for URL relevance information.
     */
    public static class URLData {
        public final String url;
        public final int score;
        public final long timestamp;
        
        public URLData(String url, int score) {
            this.url = url;
            this.score = score;
            this.timestamp = System.currentTimeMillis();
        }
        
        @Override
        public String toString() {
            return "URL: " + url + " (Score: " + score + ")";
        }
    }
}
