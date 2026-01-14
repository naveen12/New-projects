package burp.relevance;

import burp.IBurpExtenderCallbacks;
import burp.core.CoreEngine;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.List;

/**
 * URLRelevanceUI: Provides a UI for viewing and filtering URLs by relevance score.
 * Displays a sortable table with URL Relevance scores and filter options.
 */
public class URLRelevanceUI extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private final URLRelevanceEngine urlEngine;
    private final URLTableModel tableModel;
    private JTable urlTable;
    private JCheckBox filterCheckBox;
    
    public URLRelevanceUI(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        this.urlEngine = new URLRelevanceEngine();
        this.tableModel = new URLTableModel();
        
        initComponents();
    }
    
    /**
     * Initialize UI components.
     */
    private void initComponents() {
        setLayout(new BorderLayout());
        
        // Top panel with filter controls
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        
        filterCheckBox = new JCheckBox("Show only attackable URLs (Score >= 5)");
        filterCheckBox.addActionListener((ActionEvent e) -> {
            urlEngine.setShowOnlyAttackableURLs(filterCheckBox.isSelected());
            refreshTable();
        });
        controlPanel.add(filterCheckBox);
        
        JButton clearButton = new JButton("Clear All URLs");
        clearButton.addActionListener((ActionEvent e) -> {
            tableModel.clear();
            urlEngine.urlDataMap.clear();
        });
        controlPanel.add(clearButton);
        
        JButton exportButton = new JButton("Export URLs");
        exportButton.addActionListener((ActionEvent e) -> exportURLs());
        controlPanel.add(exportButton);
        
        add(controlPanel, BorderLayout.NORTH);
        
        // Table for displaying URLs
        urlTable = new JTable(tableModel);
        urlTable.setAutoCreateRowSorter(true);
        urlTable.getColumnModel().getColumn(1).setMaxWidth(80);
        
        JScrollPane scrollPane = new JScrollPane(urlTable);
        add(scrollPane, BorderLayout.CENTER);
    }
    
    /**
     * Add a URL transaction to the table.
     */
    public void addURL(CoreEngine.HttpTransaction transaction) {
        int score = coreEngine.calculateURLScore(transaction.requestInfo, transaction.responseInfo);
        urlEngine.addURL(transaction.url, score);
        tableModel.addURL(transaction.url, score);
        refreshTable();
    }
    
    /**
     * Refresh the table display based on current filter settings.
     */
    private void refreshTable() {
        List<URLRelevanceEngine.URLData> filteredURLs = urlEngine.getURLs(
                filterCheckBox.isSelected()
        );
        tableModel.setURLs(filteredURLs);
    }
    
    /**
     * Export URLs to a text file.
     */
    private void exportURLs() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new java.io.File("urls.txt"));
        int result = fileChooser.showSaveDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                java.io.FileWriter writer = new java.io.FileWriter(file);
                
                for (URLRelevanceEngine.URLData urlData : urlEngine.urlDataMap.values()) {
                    writer.write(urlData.url + " (Score: " + urlData.score + ")\n");
                }
                
                writer.close();
                JOptionPane.showMessageDialog(this, "URLs exported successfully!");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error exporting URLs: " + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Table model for displaying URLs.
     */
    private static class URLTableModel extends AbstractTableModel {
        private final List<URLRelevanceEngine.URLData> urls = new ArrayList<>();
        private final String[] columnNames = {"URL", "Score"};
        
        public void addURL(String url, int score) {
            // Avoid duplicates by checking if URL already exists
            for (URLRelevanceEngine.URLData existing : urls) {
                if (existing.url.equals(url)) {
                    return;
                }
            }
            urls.add(0, new URLRelevanceEngine.URLData(url, score));
            fireTableDataChanged();
        }
        
        public void setURLs(List<URLRelevanceEngine.URLData> urlList) {
            urls.clear();
            urls.addAll(urlList);
            fireTableDataChanged();
        }
        
        public void clear() {
            urls.clear();
            fireTableDataChanged();
        }
        
        @Override
        public int getRowCount() {
            return urls.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            URLRelevanceEngine.URLData data = urls.get(rowIndex);
            return columnIndex == 0 ? data.url : data.score;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 1 ? Integer.class : String.class;
        }
    }
}
