package burp;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

/**
 * Export results in multiple formats
 */
public class CariddiExporter {
    public static void export(List<CariddiResult> results, String filePath, String format) throws IOException {
        switch (format.toLowerCase()) {
            case "json":
                exportAsJson(results, filePath);
                break;
            case "csv":
                exportAsCsv(results, filePath);
                break;
            case "xml":
                exportAsXml(results, filePath);
                break;
            case "txt":
                exportAsTxt(results, filePath);
                break;
            default:
                throw new IllegalArgumentException("Unsupported format: " + format);
        }
    }

    private static void exportAsJson(List<CariddiResult> results, String filePath) throws IOException {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"results\": [\n");

        for (int i = 0; i < results.size(); i++) {
            CariddiResult result = results.get(i);
            json.append("    {\n");
            json.append("      \"type\": \"").append(escapeJson(result.getType())).append("\",\n");
            json.append("      \"url\": \"").append(escapeJson(result.getUrl())).append("\",\n");
            json.append("      \"finding\": \"").append(escapeJson(result.getFinding())).append("\",\n");
            json.append("      \"severity\": \"").append(escapeJson(result.getSeverity())).append("\",\n");
            json.append("      \"details\": \"").append(escapeJson(result.getDetails())).append("\"\n");
            json.append("    }");
            if (i < results.size() - 1) {
                json.append(",");
            }
            json.append("\n");
        }

        json.append("  ],\n");
        json.append("  \"total\": ").append(results.size()).append(",\n");
        json.append("  \"generated\": \"").append(new java.util.Date()).append("\"\n");
        json.append("}\n");

        writeToFile(filePath, json.toString());
    }

    private static void exportAsCsv(List<CariddiResult> results, String filePath) throws IOException {
        StringBuilder csv = new StringBuilder();
        // Header
        csv.append("Type,URL,Finding,Severity,Details\n");

        // Data
        for (CariddiResult result : results) {
            csv.append("\"").append(escapeCsv(result.getType())).append("\",");
            csv.append("\"").append(escapeCsv(result.getUrl())).append("\",");
            csv.append("\"").append(escapeCsv(result.getFinding())).append("\",");
            csv.append("\"").append(escapeCsv(result.getSeverity())).append("\",");
            csv.append("\"").append(escapeCsv(result.getDetails())).append("\"\n");
        }

        writeToFile(filePath, csv.toString());
    }

    private static void exportAsXml(List<CariddiResult> results, String filePath) throws IOException {
        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<cariddi>\n");
        xml.append("  <metadata>\n");
        xml.append("    <generated>").append(new java.util.Date()).append("</generated>\n");
        xml.append("    <totalResults>").append(results.size()).append("</totalResults>\n");
        xml.append("  </metadata>\n");
        xml.append("  <results>\n");

        for (CariddiResult result : results) {
            xml.append("    <result>\n");
            xml.append("      <type>").append(escapeXml(result.getType())).append("</type>\n");
            xml.append("      <url>").append(escapeXml(result.getUrl())).append("</url>\n");
            xml.append("      <finding>").append(escapeXml(result.getFinding())).append("</finding>\n");
            xml.append("      <severity>").append(escapeXml(result.getSeverity())).append("</severity>\n");
            xml.append("      <details>").append(escapeXml(result.getDetails())).append("</details>\n");
            xml.append("    </result>\n");
        }

        xml.append("  </results>\n");
        xml.append("</cariddi>\n");

        writeToFile(filePath, xml.toString());
    }

    private static void exportAsTxt(List<CariddiResult> results, String filePath) throws IOException {
        StringBuilder txt = new StringBuilder();
        txt.append("CARIDDI SCAN RESULTS\n");
        txt.append("Generated: ").append(new java.util.Date()).append("\n");
        txt.append("Total Results: ").append(results.size()).append("\n");
        txt.append("========================================\n\n");

        // Group by type
        java.util.Map<String, java.util.List<CariddiResult>> grouped = new java.util.LinkedHashMap<>();
        for (CariddiResult result : results) {
            grouped.computeIfAbsent(result.getType(), k -> new java.util.ArrayList<>()).add(result);
        }

        // Print grouped results
        for (String type : grouped.keySet()) {
            txt.append(type.toUpperCase()).append(" FINDINGS (").append(grouped.get(type).size()).append(")\n");
            txt.append("----------------------------------------\n");

            for (CariddiResult result : grouped.get(type)) {
                txt.append("URL: ").append(result.getUrl()).append("\n");
                txt.append("Finding: ").append(result.getFinding()).append("\n");
                txt.append("Severity: ").append(result.getSeverity()).append("\n");
                txt.append("Details: ").append(result.getDetails()).append("\n");
                txt.append("\n");
            }
        }

        txt.append("========================================\n");
        txt.append("End of Report\n");

        writeToFile(filePath, txt.toString());
    }

    private static void writeToFile(String filePath, String content) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(content);
        }
    }

    private static String escapeJson(String str) {
        if (str == null) return "";
        return str.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static String escapeCsv(String str) {
        if (str == null) return "";
        return str.replace("\"", "\"\"");
    }

    private static String escapeXml(String str) {
        if (str == null) return "";
        return str.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
