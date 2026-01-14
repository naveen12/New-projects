package burp.integrations;

import java.io.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SemgrepIntegration: Handles integration with Semgrep code scanner.
 * Scans JavaScript and API responses for code vulnerabilities.
 */
public class SemgrepIntegration {
    
    /**
     * Scan content with Semgrep (requires Semgrep to be installed).
     */
    public static List<SemgrepFinding> scanWithSemgrep(String content, String scanType) {
        List<SemgrepFinding> findings = new ArrayList<>();
        
        try {
            // Create temporary file with content
            File tempFile = File.createTempFile("semgrep_scan", ".tmp");
            try (FileWriter fw = new FileWriter(tempFile)) {
                fw.write(content);
            }
            
            // Run Semgrep command (requires Semgrep CLI)
            ProcessBuilder pb = new ProcessBuilder("semgrep", "--json", tempFile.getAbsolutePath());
            Process process = pb.start();
            
            // Read and parse results
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder jsonOutput = new StringBuilder();
            
            while ((line = reader.readLine()) != null) {
                jsonOutput.append(line);
            }
            
            // Parse JSON output (simplified)
            findings = parseSemgrepJSON(jsonOutput.toString());
            
            // Clean up
            tempFile.delete();
        } catch (Exception e) {
            System.err.println("Error running Semgrep: " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Parse Semgrep JSON output.
     */
    private static List<SemgrepFinding> parseSemgrepJSON(String jsonOutput) {
        List<SemgrepFinding> findings = new ArrayList<>();
        
        try {
            // Simple regex-based JSON parsing for vulnerability patterns
            Pattern pattern = Pattern.compile("\"rule_id\":\"([^\"]+)\".*?\"message\":\"([^\"]+)\".*?\"severity\":\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(jsonOutput);
            
            while (matcher.find()) {
                String ruleId = matcher.group(1);
                String message = matcher.group(2);
                String severity = matcher.group(3);
                
                findings.add(new SemgrepFinding(ruleId, message, severity));
            }
        } catch (Exception e) {
            System.err.println("Error parsing Semgrep JSON: " + e.getMessage());
        }
        
        return findings;
    }
    
    /**
     * Data class for Semgrep findings.
     */
    public static class SemgrepFinding {
        public final String ruleId;
        public final String message;
        public final String severity;
        
        public SemgrepFinding(String ruleId, String message, String severity) {
            this.ruleId = ruleId;
            this.message = message;
            this.severity = severity;
        }
        
        @Override
        public String toString() {
            return ruleId + ": " + message + " [" + severity + "]";
        }
    }
}
