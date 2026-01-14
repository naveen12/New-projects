package burp.reporting;

import burp.integrations.OwaspMapping;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.File;

/**
 * ReportingUI: Provides UI for generating and exporting vulnerability reports.
 * Generates professional Markdown reports with all findings and remediation details.
 */
public class ReportingUI extends JPanel {
    private JTextArea reportTextArea;
    private JButton generateReportButton;
    private JButton exportReportButton;
    private JButton clearButton;
    private ReportGenerator reportGenerator;
    
    public ReportingUI() {
        reportGenerator = new ReportGenerator();
        initComponents();
    }

    /**
     * Initialize UI components.
     */
    private void initComponents() {
        setLayout(new BorderLayout());

        // Main report text area
        reportTextArea = new JTextArea();
        reportTextArea.setEditable(false);
        reportTextArea.setFont(new Font("Courier New", Font.PLAIN, 11));
        JScrollPane scrollPane = new JScrollPane(reportTextArea);

        // Button panel
        generateReportButton = new JButton("Generate Sample Report");
        generateReportButton.addActionListener((ActionEvent e) -> generateSampleReport());

        exportReportButton = new JButton("Export Report to Markdown");
        exportReportButton.addActionListener((ActionEvent e) -> exportReport());
        exportReportButton.setEnabled(false);
        
        clearButton = new JButton("Clear Report");
        clearButton.addActionListener((ActionEvent e) -> {
            reportTextArea.setText("");
            exportReportButton.setEnabled(false);
        });

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttonPanel.add(generateReportButton);
        buttonPanel.add(exportReportButton);
        buttonPanel.add(clearButton);
        
        // Custom report panel
        JPanel customPanel = createCustomReportPanel();

        // Main layout
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, 
                customPanel, scrollPane);
        splitPane.setDividerLocation(300);
        
        add(buttonPanel, BorderLayout.NORTH);
        add(splitPane, BorderLayout.CENTER);
    }
    
    /**
     * Create custom report generation panel.
     */
    private JPanel createCustomReportPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Custom Report Generator"));
        
        // Title input
        panel.add(new JLabel("Vulnerability Title:"));
        JTextField titleField = new JTextField(15);
        panel.add(titleField);
        panel.add(Box.createVerticalStrut(5));
        
        // Severity selector
        panel.add(new JLabel("Severity:"));
        String[] severities = {"Low", "Medium", "High", "Critical"};
        JComboBox<String> severityCombo = new JComboBox<>(severities);
        panel.add(severityCombo);
        panel.add(Box.createVerticalStrut(5));
        
        // Summary
        panel.add(new JLabel("Summary:"));
        JTextArea summaryArea = new JTextArea(3, 20);
        summaryArea.setLineWrap(true);
        panel.add(new JScrollPane(summaryArea));
        panel.add(Box.createVerticalStrut(5));
        
        // Steps to reproduce
        panel.add(new JLabel("Steps to Reproduce:"));
        JTextArea stepsArea = new JTextArea(3, 20);
        stepsArea.setLineWrap(true);
        panel.add(new JScrollPane(stepsArea));
        panel.add(Box.createVerticalStrut(5));
        
        // Impact
        panel.add(new JLabel("Impact:"));
        JTextArea impactArea = new JTextArea(2, 20);
        impactArea.setLineWrap(true);
        panel.add(new JScrollPane(impactArea));
        panel.add(Box.createVerticalStrut(5));
        
        // Remediation
        panel.add(new JLabel("Remediation:"));
        JTextArea remediationArea = new JTextArea(2, 20);
        remediationArea.setLineWrap(true);
        panel.add(new JScrollPane(remediationArea));
        panel.add(Box.createVerticalStrut(10));
        
        // Generate button
        JButton generateCustomButton = new JButton("Generate Custom Report");
        generateCustomButton.addActionListener((ActionEvent e) -> {
            String title = titleField.getText();
            String severity = (String) severityCombo.getSelectedItem();
            String summary = summaryArea.getText();
            String steps = stepsArea.getText();
            String impact = impactArea.getText();
            String remediation = remediationArea.getText();
            String owasp = ReportGenerator.mapToOWASP(title);
            
            if (title.isEmpty() || summary.isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Please fill in all required fields!",
                        "Error", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            String report = reportGenerator.generateReport(
                    title, severity, summary, steps,
                    "GET /example HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0",
                    "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>...</html>",
                    impact, remediation, owasp
            );
            
            reportTextArea.setText(report);
            exportReportButton.setEnabled(true);
        });
        panel.add(generateCustomButton);
        panel.add(Box.createVerticalGlue());
        
        JPanel container = new JPanel(new BorderLayout());
        container.add(new JScrollPane(panel), BorderLayout.CENTER);
        return container;
    }

    /**
     * Generate a sample vulnerability report for demonstration.
     */
    private void generateSampleReport() {
        String report = reportGenerator.generateReport(
                "SQL Injection in Login Form",
                "Critical",
                "A SQL injection vulnerability was discovered in the login form. The application fails to properly sanitize user input, allowing an attacker to execute arbitrary SQL commands.",
                "1. Navigate to the login page\n2. Enter ' OR '1'='1 in the username field\n3. Enter any password\n4. Click login\n5. The application allows access without valid credentials",
                "POST /login HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=' OR '1'='1&password=test",
                "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>Welcome Admin!</body></html>",
                "An attacker can bypass authentication, access unauthorized data, modify database content, or execute administrative operations.",
                "1. Use parameterized queries (prepared statements)\n2. Implement input validation\n3. Use ORM frameworks\n4. Apply principle of least privilege to database accounts",
                OwaspMapping.getOwaspCategory("SQL Injection")
        );
        
        reportTextArea.setText(report);
        exportReportButton.setEnabled(true);
    }

    /**
     * Export the generated report to a Markdown file.
     */
    private void exportReport() {
        if (reportTextArea.getText().isEmpty()) {
            JOptionPane.showMessageDialog(this, "No report to export. Generate a report first.",
                    "Warning", JOptionPane.WARNING_MESSAGE);
            return;
        }
        
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Vulnerability Report");
        fileChooser.setSelectedFile(new File("vulnerability_report.md"));
        int userSelection = fileChooser.showSaveDialog(this);
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            File fileToSave = fileChooser.getSelectedFile();
            try {
                java.io.PrintWriter writer = new java.io.PrintWriter(fileToSave);
                writer.println(reportTextArea.getText());
                writer.close();
                JOptionPane.showMessageDialog(this, 
                        "Report exported successfully to:\n" + fileToSave.getAbsolutePath(),
                        "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (java.io.FileNotFoundException e) {
                JOptionPane.showMessageDialog(this, 
                        "Error saving report: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
