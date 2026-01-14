package burp.accesstrol;

/**
 * AccessControlIssue: Represents a detected access control issue.
 */
public class AccessControlIssue {
    public enum Severity {
        LOW("Low"),
        MEDIUM("Medium"),
        HIGH("High"),
        CRITICAL("Critical");
        
        private final String label;
        Severity(String label) {
            this.label = label;
        }
        
        public String getLabel() {
            return label;
        }
    }
    
    public final String url;
    public final String testName;
    public final String finding;
    public final Severity severity;
    public final int originalStatus;
    public final int modifiedStatus;
    public final int originalLength;
    public final int modifiedLength;
    public final long timestamp;
    
    public AccessControlIssue(String url, String testName, String finding, Severity severity,
                             int originalStatus, int modifiedStatus, int originalLength, int modifiedLength) {
        this.url = url;
        this.testName = testName;
        this.finding = finding;
        this.severity = severity;
        this.originalStatus = originalStatus;
        this.modifiedStatus = modifiedStatus;
        this.originalLength = originalLength;
        this.modifiedLength = modifiedLength;
        this.timestamp = System.currentTimeMillis();
    }
}
