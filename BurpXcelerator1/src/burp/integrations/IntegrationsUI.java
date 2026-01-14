package burp.integrations;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.*;
import java.util.List;

/**
 * IntegrationsUI: Provides UI for integrating external tools like Nuclei and Semgrep.
 * Enables export of URLs for scanning and parsing of results.
 */
public class IntegrationsUI extends JPanel {
    
    public IntegrationsUI() {
        initComponents();
    }

    /**
     * Initialize UI components.
     */
    private void initComponents() {
        setLayout(new BorderLayout());

        // Main panel with integration options
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Nuclei section
        JPanel nucleiPanel = createNucleiPanel();
        mainPanel.add(nucleiPanel);
        mainPanel.add(Box.createVerticalStrut(15));

        // Semgrep section
        JPanel semgrepPanel = createSemgrepPanel();
        mainPanel.add(semgrepPanel);
        mainPanel.add(Box.createVerticalStrut(15));

        // OWASP Mapping section
        JPanel owaspPanel = createOwaspPanel();
        mainPanel.add(owaspPanel);
        mainPanel.add(Box.createVerticalGlue());

        JScrollPane scrollPane = new JScrollPane(mainPanel);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Create Nuclei integration panel.
     */
    private JPanel createNucleiPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Nuclei Integration"));

        JLabel nucleiLabel = new JLabel("Export URLs for Nuclei scanning:");
        JButton exportNucleiButton = new JButton("Export URLs for Nuclei");
        exportNucleiButton.addActionListener((ActionEvent e) -> exportURLsForNuclei());

        JLabel nucleiResultLabel = new JLabel("Parse Nuclei Results:");
        JButton parseNucleiButton = new JButton("Load Nuclei Results");
        parseNucleiButton.addActionListener((ActionEvent e) -> parseNucleiResults());

        panel.add(nucleiLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(exportNucleiButton);
        panel.add(Box.createVerticalStrut(10));
        panel.add(nucleiResultLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(parseNucleiButton);

        return panel;
    }

    /**
     * Create Semgrep integration panel.
     */
    private JPanel createSemgrepPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("Semgrep Integration"));

        JLabel semgrepLabel = new JLabel("Scan JavaScript/API responses with Semgrep:");
        JButton scanSemgrepButton = new JButton("Scan with Semgrep");
        scanSemgrepButton.addActionListener((ActionEvent e) -> scanWithSemgrep());

        JLabel semgrepNoteLabel = new JLabel("(Requires Semgrep CLI to be installed)");
        semgrepNoteLabel.setFont(semgrepNoteLabel.getFont().deriveFont(Font.ITALIC));

        panel.add(semgrepLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(scanSemgrepButton);
        panel.add(Box.createVerticalStrut(5));
        panel.add(semgrepNoteLabel);

        return panel;
    }

    /**
     * Create OWASP mapping panel.
     */
    private JPanel createOwaspPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createTitledBorder("OWASP Top 10 Mapping"));

        JLabel owaspLabel = new JLabel("View OWASP Top 10 2021 Categories:");
        JButton viewOwaspButton = new JButton("View OWASP Categories");
        viewOwaspButton.addActionListener((ActionEvent e) -> viewOwaspCategories());

        panel.add(owaspLabel);
        panel.add(Box.createVerticalStrut(5));
        panel.add(viewOwaspButton);

        return panel;
    }

    /**
     * Export URLs for Nuclei scanning.
     */
    private void exportURLsForNuclei() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new java.io.File("urls_for_nuclei.txt"));
        int result = fileChooser.showSaveDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            JOptionPane.showMessageDialog(this,
                    "Nuclei integration: Export URLs from the URL Relevance tab.\n" +
                            "Then run: nuclei -l urls_for_nuclei.txt -o nuclei_results.txt",
                    "Nuclei Export", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * Parse Nuclei scan results.
     */
    private void parseNucleiResults() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(this);

        if (result == JFileChooser.APPROVE_OPTION) {
            java.io.File file = fileChooser.getSelectedFile();
            List<NucleiIntegration.NucleiResult> results = NucleiIntegration.parseNucleiResults(file.getAbsolutePath());

            if (results.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No Nuclei results found or invalid file format.",
                        "Parse Results", JOptionPane.WARNING_MESSAGE);
            } else {
                StringBuilder sb = new StringBuilder("Found " + results.size() + " findings:\n\n");
                for (NucleiIntegration.NucleiResult r : results) {
                    sb.append(r.toString()).append("\n");
                }
                JTextArea textArea = new JTextArea(sb.toString());
                textArea.setEditable(false);
                JScrollPane scrollPane = new JScrollPane(textArea);
                scrollPane.setPreferredSize(new Dimension(600, 300));
                JOptionPane.showMessageDialog(this, scrollPane, "Nuclei Results", JOptionPane.INFORMATION_MESSAGE);
            }
        }
    }

    /**
     * Scan with Semgrep.
     */
    private void scanWithSemgrep() {
        JOptionPane.showMessageDialog(this,
                "Semgrep integration: Make sure Semgrep CLI is installed.\n" +
                        "Scan JS/API responses from the captured traffic.\n" +
                        "Use: semgrep --config=p/owasp-top-ten your_file.js",
                "Semgrep Scanning", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * View OWASP Top 10 categories.
     */
    private void viewOwaspCategories() {
        Collection<String> categories = OwaspMapping.getAllCategories();
        StringBuilder sb = new StringBuilder("OWASP Top 10 2021 Categories:\n\n");

        List<String> sortedCategories = new ArrayList<>(categories);
        Collections.sort(sortedCategories);

        for (String category : sortedCategories) {
            sb.append("• ").append(category).append("\n");
        }

        JTextArea textArea = new JTextArea(sb.toString());
        textArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(500, 300));
        JOptionPane.showMessageDialog(this, scrollPane, "OWASP Top 10 2021", JOptionPane.INFORMATION_MESSAGE);
    }
}
