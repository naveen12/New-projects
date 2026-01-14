package burp.integrations;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * NucleiIntegration: Handles integration with Nuclei vulnerability scanner.
 * Exports URLs to a file and parses Nuclei scan results.
 */
public class NucleiIntegration {
    
    /**
     * Export URLs to a file for Nuclei scanning.
     */
    public static boolean exportURLsForNuclei(List<String> urls, String filePath) {
        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter(filePath));
            for (String url : urls) {
                writer.write(url);
                writer.newLine();
            }
            writer.close();
            return true;
        } catch (IOException e) {
            System.err.println("Error exporting URLs for Nuclei: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Parse Nuclei scan results from a JSON or text file.
     */
    public static List<NucleiResult> parseNucleiResults(String filePath) {
        List<NucleiResult> results = new ArrayList<>();
        try {
            BufferedReader reader = new BufferedReader(new FileReader(filePath));
            String line;
            while ((line = reader.readLine()) != null) {
                NucleiResult result = parseNucleiLine(line);
                if (result != null) {
                    results.add(result);
                }
            }
            reader.close();
        } catch (IOException e) {
            System.err.println("Error parsing Nuclei results: " + e.getMessage());
        }
        return results;
    }
    
    /**
     * Parse a single Nuclei result line.
     */
    private static NucleiResult parseNucleiLine(String line) {
        try {
            // Simple parsing for JSON-like output
            if (line.contains("\"url\":") && line.contains("\"template-id\":")) {
                Pattern urlPattern = Pattern.compile("\"url\":\"([^\"]+)\"");
                Pattern templatePattern = Pattern.compile("\"template-id\":\"([^\"]+)\"");
                Pattern severityPattern = Pattern.compile("\"severity\":\"([^\"]+)\"");
                
                Matcher urlMatcher = urlPattern.matcher(line);
                Matcher templateMatcher = templatePattern.matcher(line);
                Matcher severityMatcher = severityPattern.matcher(line);
                
                String url = urlMatcher.find() ? urlMatcher.group(1) : "Unknown";
                String templateId = templateMatcher.find() ? templateMatcher.group(1) : "Unknown";
                String severity = severityMatcher.find() ? severityMatcher.group(1) : "Unknown";
                
                return new NucleiResult(url, templateId, severity);
            }
        } catch (Exception e) {
            System.err.println("Error parsing Nuclei line: " + e.getMessage());
        }
        return null;
    }
    
    /**
     * Data class for Nuclei scan results.
     */
    public static class NucleiResult {
        public final String url;
        public final String templateId;
        public final String severity;
        
        public NucleiResult(String url, String templateId, String severity) {
            this.url = url;
            this.templateId = templateId;
            this.severity = severity;
        }
        
        @Override
        public String toString() {
            return url + " (" + templateId + ") [" + severity + "]";
        }
    }
}
