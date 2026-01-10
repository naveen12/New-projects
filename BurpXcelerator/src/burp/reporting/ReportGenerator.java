package burp.reporting;

public class ReportGenerator {

    public String generateReport(String title, String severity, String summary, String steps, String request, String response, String impact, String remediation, String owasp) {
        StringBuilder sb = new StringBuilder();
        sb.append("# Vulnerability Report: ").append(title).append("\n\n");
        sb.append("## Severity: ").append(severity).append("\n\n");
        sb.append("## OWASP Category: ").append(owasp).append("\n\n");
        sb.append("## Summary\n").append(summary).append("\n\n");
        sb.append("## Steps to Reproduce\n").append(steps).append("\n\n");
        sb.append("## Request\n```\n").append(request).append("\n```\n\n");
        sb.append("## Response\n```\n").append(response).append("\n```\n\n");
        sb.append("## Impact\n").append(impact).append("\n\n");
        sb.append("## Remediation\n").append(remediation).append("\n\n");
        return sb.toString();
    }
}

