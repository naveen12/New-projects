package burp;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Main UI for Cariddi Burp Extension
 */
public class CariddiUI {
    private JPanel mainPanel;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private CariddiScanner scanner;
    private CariddiScanTab scanTab;
    private CariddiHelpTab helpTab;
    private JTabbedPane tabbedPane;

    public CariddiUI(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr) {
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.stderr = stderr;
        this.scanner = new CariddiScanner(callbacks, stdout, stderr);
        
        initializeUI();
    }

    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        tabbedPane = new JTabbedPane();

        // Create tabs
        scanTab = new CariddiScanTab(callbacks, stdout, stderr, scanner);
        helpTab = new CariddiHelpTab();

        // Add tabs
        tabbedPane.addTab("Scanner", scanTab.getPanel());
        tabbedPane.addTab("Results", scanTab.getResultsPanel());
        tabbedPane.addTab("Settings", scanTab.getSettingsPanel());
        tabbedPane.addTab("Help", helpTab.getPanel());

        mainPanel.add(tabbedPane, BorderLayout.CENTER);
    }

    public JPanel getMainPanel() {
        return mainPanel;
    }
}

/**
 * Scan configuration and input tab
 */
class CariddiScanTab {
    private JPanel mainPanel;
    private JPanel resultsPanel;
    private JPanel settingsPanel;
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private CariddiScanner scanner;
    
    private JTextArea urlInputArea;
    private JTable resultsTable;
    private CariddiResultsModel resultsModel;
    private JButton startScanButton;
    private JButton stopScanButton;
    private JButton clearButton;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    
    // Settings
    private JCheckBox huntEndpointsCheckBox;
    private JCheckBox huntSecretsCheckBox;
    private JCheckBox huntErrorsCheckBox;
    private JCheckBox huntInfoCheckBox;
    private JSpinner extensionLevelSpinner;
    private JSpinner concurrencySpinner;
    private JSpinner timeoutSpinner;
    private JSpinner depthSpinner;
    private JCheckBox intensiveCheckBox;
    private JTextField customHeadersField;
    private JTextField userAgentField;

    public CariddiScanTab(IBurpExtenderCallbacks callbacks, PrintWriter stdout, PrintWriter stderr, CariddiScanner scanner) {
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.stderr = stderr;
        this.scanner = scanner;
        this.resultsModel = new CariddiResultsModel();
        
        initializeScanPanel();
        initializeResultsPanel();
        initializeSettingsPanel();
    }

    private void initializeScanPanel() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Input section
        JPanel inputPanel = new JPanel(new BorderLayout(5, 5));
        inputPanel.setBorder(BorderFactory.createTitledBorder("Target URLs (one per line)"));
        
        urlInputArea = new JTextArea(8, 80);
        urlInputArea.setLineWrap(false);
        urlInputArea.setWrapStyleWord(false);
        urlInputArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        JScrollPane inputScroll = new JScrollPane(urlInputArea);
        inputPanel.add(inputScroll, BorderLayout.CENTER);

        // Buttons panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        
        startScanButton = new JButton("Start Scan");
        stopScanButton = new JButton("Stop Scan");
        clearButton = new JButton("Clear URLs");
        stopScanButton.setEnabled(false);
        
        startScanButton.addActionListener(e -> startScan());
        stopScanButton.addActionListener(e -> stopScan());
        clearButton.addActionListener(e -> urlInputArea.setText(""));

        buttonPanel.add(startScanButton);
        buttonPanel.add(stopScanButton);
        buttonPanel.add(clearButton);

        // Status panel
        JPanel statusPanel = new JPanel(new BorderLayout(5, 5));
        statusLabel = new JLabel("Ready");
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        statusPanel.add(new JLabel("Status: "), BorderLayout.WEST);
        statusPanel.add(statusLabel, BorderLayout.CENTER);
        statusPanel.add(progressBar, BorderLayout.EAST);

        inputPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        mainPanel.add(inputPanel, BorderLayout.NORTH);
        mainPanel.add(statusPanel, BorderLayout.CENTER);
    }

    private void initializeResultsPanel() {
        resultsPanel = new JPanel(new BorderLayout(5, 5));
        resultsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Results table
        resultsTable = new JTable(resultsModel);
        resultsTable.setDefaultRenderer(Object.class, new CariddiResultsRenderer());
        resultsTable.setRowHeight(25);
        resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        resultsPanel.add(tableScroll, BorderLayout.CENTER);

        // Export buttons
        JPanel exportPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        exportPanel.setBorder(BorderFactory.createTitledBorder("Export Results"));
        
        JButton exportJsonButton = new JButton("Export as JSON");
        JButton exportCsvButton = new JButton("Export as CSV");
        JButton exportXmlButton = new JButton("Export as XML");
        JButton exportTxtButton = new JButton("Export as TXT");
        JButton copyButton = new JButton("Copy Selected");

        exportJsonButton.addActionListener(e -> exportResults("json"));
        exportCsvButton.addActionListener(e -> exportResults("csv"));
        exportXmlButton.addActionListener(e -> exportResults("xml"));
        exportTxtButton.addActionListener(e -> exportResults("txt"));
        copyButton.addActionListener(e -> copySelectedRows());

        exportPanel.add(exportJsonButton);
        exportPanel.add(exportCsvButton);
        exportPanel.add(exportXmlButton);
        exportPanel.add(exportTxtButton);
        exportPanel.add(new JSeparator(JSeparator.VERTICAL));
        exportPanel.add(copyButton);

        resultsPanel.add(exportPanel, BorderLayout.SOUTH);
    }

    private void initializeSettingsPanel() {
        settingsPanel = new JPanel();
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));

        // Scan options
        JPanel scanOptionsPanel = new JPanel();
        scanOptionsPanel.setBorder(BorderFactory.createTitledBorder("Scan Options"));
        scanOptionsPanel.setLayout(new GridLayout(0, 2, 10, 10));
        
        huntEndpointsCheckBox = new JCheckBox("Hunt for Endpoints", true);
        huntSecretsCheckBox = new JCheckBox("Hunt for Secrets", true);
        huntErrorsCheckBox = new JCheckBox("Hunt for Errors", false);
        huntInfoCheckBox = new JCheckBox("Hunt for Info", false);
        intensiveCheckBox = new JCheckBox("Intensive Mode (scan subdomains)", false);
        
        JLabel extLevelLabel = new JLabel("File Extension Level (1-7):");
        extensionLevelSpinner = new JSpinner(new SpinnerNumberModel(2, 1, 7, 1));

        scanOptionsPanel.add(huntEndpointsCheckBox);
        scanOptionsPanel.add(huntSecretsCheckBox);
        scanOptionsPanel.add(huntErrorsCheckBox);
        scanOptionsPanel.add(huntInfoCheckBox);
        scanOptionsPanel.add(intensiveCheckBox);
        scanOptionsPanel.add(new JLabel(""));
        scanOptionsPanel.add(extLevelLabel);
        scanOptionsPanel.add(extensionLevelSpinner);

        // Performance options
        JPanel performancePanel = new JPanel();
        performancePanel.setBorder(BorderFactory.createTitledBorder("Performance & Timeout"));
        performancePanel.setLayout(new GridLayout(0, 2, 10, 10));

        JLabel concLabel = new JLabel("Concurrency Level:");
        concurrencySpinner = new JSpinner(new SpinnerNumberModel(20, 1, 200, 5));
        JLabel timeoutLabel = new JLabel("Timeout (seconds):");
        timeoutSpinner = new JSpinner(new SpinnerNumberModel(10, 1, 60, 1));
        JLabel depthLabel = new JLabel("Max Crawl Depth:");
        depthSpinner = new JSpinner(new SpinnerNumberModel(3, 1, 10, 1));

        performancePanel.add(concLabel);
        performancePanel.add(concurrencySpinner);
        performancePanel.add(timeoutLabel);
        performancePanel.add(timeoutSpinner);
        performancePanel.add(depthLabel);
        performancePanel.add(depthSpinner);

        // Custom headers and user agent
        JPanel headerPanel = new JPanel();
        headerPanel.setBorder(BorderFactory.createTitledBorder("Custom Headers & User Agent"));
        headerPanel.setLayout(new BoxLayout(headerPanel, BoxLayout.Y_AXIS));
        
        JPanel headerInputPanel = new JPanel(new BorderLayout());
        headerInputPanel.add(new JLabel("Custom Headers: "), BorderLayout.WEST);
        customHeadersField = new JTextField("", 30);
        headerInputPanel.add(customHeadersField, BorderLayout.CENTER);
        
        JPanel uaPanel = new JPanel(new BorderLayout());
        uaPanel.add(new JLabel("User Agent: "), BorderLayout.WEST);
        userAgentField = new JTextField("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", 30);
        uaPanel.add(userAgentField, BorderLayout.CENTER);
        
        headerPanel.add(headerInputPanel);
        headerPanel.add(Box.createVerticalStrut(5));
        headerPanel.add(uaPanel);

        settingsPanel.add(scanOptionsPanel);
        settingsPanel.add(Box.createVerticalStrut(10));
        settingsPanel.add(performancePanel);
        settingsPanel.add(Box.createVerticalStrut(10));
        settingsPanel.add(headerPanel);
        settingsPanel.add(Box.createVerticalGlue());

        // Wrap in scroll pane for better layout
        JScrollPane settingsScroll = new JScrollPane(settingsPanel);
        settingsScroll.setBorder(null);
    }

    private void startScan() {
        String urlsText = urlInputArea.getText().trim();
        if (urlsText.isEmpty()) {
            JOptionPane.showMessageDialog(mainPanel, "Please enter at least one URL", "No URLs", JOptionPane.WARNING_MESSAGE);
            return;
        }

        String[] urls = urlsText.split("\n");
        for (int i = 0; i < urls.length; i++) {
            urls[i] = urls[i].trim();
        }

        startScanButton.setEnabled(false);
        stopScanButton.setEnabled(true);
        statusLabel.setText("Scanning...");
        progressBar.setValue(0);

        // Create scan config
        CariddiConfig config = new CariddiConfig();
        config.setHuntEndpoints(huntEndpointsCheckBox.isSelected());
        config.setHuntSecrets(huntSecretsCheckBox.isSelected());
        config.setHuntErrors(huntErrorsCheckBox.isSelected());
        config.setHuntInfo(huntInfoCheckBox.isSelected());
        config.setIntensive(intensiveCheckBox.isSelected());
        config.setExtensionLevel((Integer) extensionLevelSpinner.getValue());
        config.setConcurrency((Integer) concurrencySpinner.getValue());
        config.setTimeout((Integer) timeoutSpinner.getValue());
        config.setMaxDepth((Integer) depthSpinner.getValue());
        config.setCustomHeaders(customHeadersField.getText());
        config.setUserAgent(userAgentField.getText());
        config.setUrls(urls);

        // Run scan in background thread
        new Thread(() -> {
            try {
                scanner.performScan(config, new CariddiScanProgressListener() {
                    @Override
                    public void onProgress(int percent) {
                        SwingUtilities.invokeLater(() -> progressBar.setValue(percent));
                    }

                    @Override
                    public void onResultFound(CariddiResult result) {
                        SwingUtilities.invokeLater(() -> {
                            resultsModel.addResult(result);
                            resultsTable.repaint();
                        });
                    }

                    @Override
                    public void onStatusUpdate(String message) {
                        SwingUtilities.invokeLater(() -> statusLabel.setText(message));
                    }

                    @Override
                    public void onComplete() {
                        SwingUtilities.invokeLater(() -> {
                            startScanButton.setEnabled(true);
                            stopScanButton.setEnabled(false);
                            statusLabel.setText("Scan complete! Found " + resultsModel.getRowCount() + " results");
                            progressBar.setValue(100);
                        });
                    }
                });
            } catch (Exception e) {
                stderr.println("[!] Error during scan: " + e.getMessage());
                e.printStackTrace(stderr);
                SwingUtilities.invokeLater(() -> {
                    startScanButton.setEnabled(true);
                    stopScanButton.setEnabled(false);
                    statusLabel.setText("Error: " + e.getMessage());
                });
            }
        }).start();
    }

    private void stopScan() {
        scanner.stopScan();
        startScanButton.setEnabled(true);
        stopScanButton.setEnabled(false);
        statusLabel.setText("Scan stopped");
    }

    private void exportResults(String format) {
        if (resultsModel.getRowCount() == 0) {
            JOptionPane.showMessageDialog(resultsPanel, "No results to export", "Empty Results", JOptionPane.WARNING_MESSAGE);
            return;
        }

        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        
        String extension = "";
        switch (format.toLowerCase()) {
            case "json":
                extension = ".json";
                fileChooser.setSelectedFile(new java.io.File("cariddi_results.json"));
                break;
            case "csv":
                extension = ".csv";
                fileChooser.setSelectedFile(new java.io.File("cariddi_results.csv"));
                break;
            case "xml":
                extension = ".xml";
                fileChooser.setSelectedFile(new java.io.File("cariddi_results.xml"));
                break;
            case "txt":
                extension = ".txt";
                fileChooser.setSelectedFile(new java.io.File("cariddi_results.txt"));
                break;
        }

        int result = fileChooser.showSaveDialog(resultsPanel);
        if (result == JFileChooser.APPROVE_OPTION) {
            java.io.File selectedFile = fileChooser.getSelectedFile();
            try {
                CariddiExporter.export(resultsModel.getResults(), selectedFile.getAbsolutePath(), format);
                JOptionPane.showMessageDialog(resultsPanel, "Results exported successfully to " + selectedFile.getAbsolutePath(), "Export Successful", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(resultsPanel, "Error exporting results: " + e.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private void copySelectedRows() {
        int[] selectedRows = resultsTable.getSelectedRows();
        if (selectedRows.length == 0) {
            JOptionPane.showMessageDialog(resultsPanel, "Please select at least one row", "No Selection", JOptionPane.WARNING_MESSAGE);
            return;
        }

        StringBuilder sb = new StringBuilder();
        for (int row : selectedRows) {
            for (int col = 0; col < resultsModel.getColumnCount(); col++) {
                sb.append(resultsModel.getValueAt(row, col)).append("\t");
            }
            sb.append("\n");
        }

        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(
            new java.awt.datatransfer.StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(resultsPanel, "Data copied to clipboard", "Success", JOptionPane.INFORMATION_MESSAGE);
    }

    public JPanel getPanel() {
        return mainPanel;
    }

    public JPanel getResultsPanel() {
        return resultsPanel;
    }

    public JPanel getSettingsPanel() {
        return settingsPanel;
    }
}

/**
 * Results table model
 */
class CariddiResultsModel extends AbstractTableModel {
    private static final String[] COLUMNS = {"Type", "URL", "Finding", "Severity", "Details"};
    private java.util.List<CariddiResult> results = new CopyOnWriteArrayList<>();

    @Override
    public int getRowCount() {
        return results.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int row, int column) {
        CariddiResult result = results.get(row);
        switch (column) {
            case 0: return result.getType();
            case 1: return result.getUrl();
            case 2: return result.getFinding();
            case 3: return result.getSeverity();
            case 4: return result.getDetails();
            default: return "";
        }
    }

    public void addResult(CariddiResult result) {
        results.add(result);
        fireTableRowsInserted(results.size() - 1, results.size() - 1);
    }

    public void clear() {
        results.clear();
        fireTableDataChanged();
    }

    public java.util.List<CariddiResult> getResults() {
        return new ArrayList<>(results);
    }
}

/**
 * Custom renderer for results
 */
class CariddiResultsRenderer extends DefaultTableCellRenderer {
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
        super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        if (!isSelected) {
            String type = (String) table.getValueAt(row, 0);
            String severity = (String) table.getValueAt(row, 3);
            
            if ("Secret".equals(type)) {
                setBackground(new Color(255, 200, 200));
            } else if ("Endpoint".equals(type)) {
                setBackground(new Color(200, 220, 255));
            } else if ("Error".equals(type)) {
                setBackground(new Color(255, 255, 200));
            } else if ("Info".equals(type)) {
                setBackground(new Color(200, 255, 200));
            }

            if ("High".equals(severity)) {
                setForeground(new Color(200, 0, 0));
            } else if ("Medium".equals(severity)) {
                setForeground(new Color(200, 100, 0));
            }
        }
        
        return this;
    }
}
