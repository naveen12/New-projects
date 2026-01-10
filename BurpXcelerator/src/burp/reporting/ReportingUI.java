package burp.reporting;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class ReportingUI extends JPanel {
    private JTextArea reportTextArea;
    private JButton generateReportButton;
    private JButton exportReportButton;

    public ReportingUI() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        reportTextArea = new JTextArea();
        JScrollPane scrollPane = new JScrollPane(reportTextArea);

        generateReportButton = new JButton("Generate Report");
        generateReportButton.addActionListener(e -> generateReport());

        exportReportButton = new JButton("Export Report to Markdown");
        exportReportButton.addActionListener(e -> exportReport());
        exportReportButton.setEnabled(false);

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(generateReportButton);
        buttonPanel.add(exportReportButton);

        add(scrollPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void generateReport() {
        ReportGenerator reportGenerator = new ReportGenerator();
        String report = reportGenerator.generateReport("SQL Injection", "High", "A sample SQL injection vulnerability was found.", "1. Go to login page.\n2. Enter ' or 1=1-- in username field.", "GET /login HTTP/1.1\nHost: example.com\n...", "HTTP/1.1 200 OK\n...", "An attacker can bypass authentication.", "Use parameterized queries.", "A03:2021-Injection");
        reportTextArea.setText(report);
        exportReportButton.setEnabled(true);
    }

    private void exportReport() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Save Report");
        fileChooser.setSelectedFile(new java.io.File("report.md"));
        int userSelection = fileChooser.showSaveDialog(this);
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            java.io.File fileToSave = fileChooser.getSelectedFile();
            try (java.io.PrintWriter writer = new java.io.PrintWriter(fileToSave)) {
                writer.println(reportTextArea.getText());
                JOptionPane.showMessageDialog(this, "Report saved successfully!", "Success", JOptionPane.INFORMATION_MESSAGE);
            } catch (java.io.FileNotFoundException e) {
                JOptionPane.showMessageDialog(this, "Error saving report: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
}
