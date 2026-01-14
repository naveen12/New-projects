package burp.accesstrol;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * AccessControlUI: Displays access control testing results in a sortable table.
 * Shows detected vulnerabilities with severity levels and detailed information.
 */
public class AccessControlUI extends JPanel {
    private final ACTableModel tableModel;
    private JTable resultsTable;
    
    public AccessControlUI() {
        this.tableModel = new ACTableModel();
        initComponents();
    }

    /**
     * Initialize UI components.
     */
    private void initComponents() {
        setLayout(new BorderLayout());
        
        // Control panel
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearButton = new JButton("Clear Results");
        clearButton.addActionListener((ActionEvent e) -> {
            tableModel.clear();
        });
        controlPanel.add(clearButton);
        
        JButton exportButton = new JButton("Export Findings");
        exportButton.addActionListener((ActionEvent e) -> exportFindings());
        controlPanel.add(exportButton);
        
        add(controlPanel, BorderLayout.NORTH);
        
        // Results table
        resultsTable = new JTable(tableModel);
        resultsTable.setAutoCreateRowSorter(true);
        resultsTable.getColumnModel().getColumn(2).setMaxWidth(100);
        
        JScrollPane scrollPane = new JScrollPane(resultsTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    /**
     * Add a test result/finding to the table.
     */
    public void addTestResult(AccessControlIssue issue) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addIssue(issue);
        });
    }
    
    /**
     * Export findings to a file.
     */
    private void exportFindings() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new java.io.File("access_control_findings.csv"));
        int result = fileChooser.showSaveDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                java.io.FileWriter writer = new java.io.FileWriter(file);
                
                // Write CSV header
                writer.write("URL,Test Name,Finding,Severity,Original Status,Modified Status,Original Length,Modified Length\n");
                
                // Write data
                for (AccessControlIssue issue : tableModel.getIssues()) {
                    writer.write("\"" + escapeCsv(issue.url) + "\",\"" + 
                            escapeCsv(issue.testName) + "\",\"" + 
                            escapeCsv(issue.finding) + "\"," + 
                            issue.severity.getLabel() + "," + 
                            issue.originalStatus + "," + 
                            issue.modifiedStatus + "," + 
                            issue.originalLength + "," + 
                            issue.modifiedLength + "\n");
                }
                
                writer.close();
                JOptionPane.showMessageDialog(this, "Findings exported successfully!");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error exporting findings: " + e.getMessage(),
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Escape CSV special characters.
     */
    private String escapeCsv(String value) {
        if (value == null) return "";
        return value.replace("\"", "\"\"").replace("\n", " ").replace("\r", " ");
    }
    
    /**
     * Table model for access control issues.
     */
    private static class ACTableModel extends AbstractTableModel {
        private final List<AccessControlIssue> issues = new ArrayList<>();
        private final String[] columnNames = {"URL", "Test", "Finding", "Severity", "Orig Status", "Mod Status", "Orig Len", "Mod Len"};
        
        public void addIssue(AccessControlIssue issue) {
            issues.add(0, issue);
            fireTableDataChanged();
        }
        
        public void clear() {
            issues.clear();
            fireTableDataChanged();
        }
        
        public List<AccessControlIssue> getIssues() {
            return new ArrayList<>(issues);
        }
        
        @Override
        public int getRowCount() {
            return issues.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            AccessControlIssue issue = issues.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return issue.url;
                case 1:
                    return issue.testName;
                case 2:
                    return issue.finding;
                case 3:
                    return issue.severity.getLabel();
                case 4:
                    return issue.originalStatus;
                case 5:
                    return issue.modifiedStatus;
                case 6:
                    return issue.originalLength;
                case 7:
                    return issue.modifiedLength;
                default:
                    return null;
            }
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 4:
                case 5:
                case 6:
                case 7:
                    return Integer.class;
                default:
                    return String.class;
            }
        }
    }
}
