package burp.parameters;

import burp.IBurpExtenderCallbacks;
import burp.core.CoreEngine;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ParameterAnalyzerUI: Provides a UI for analyzing and displaying request parameters.
 * Extracts parameters, classifies them by type, assigns risk scores, and displays
 * results in a sortable Swing table.
 */
public class ParameterAnalyzerUI extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private final ParameterTableModel tableModel;
    private JTable parameterTable;
    private final Map<String, Integer> parameterRiskMap;
    
    public ParameterAnalyzerUI(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        this.tableModel = new ParameterTableModel();
        this.parameterRiskMap = new HashMap<>();
        
        initComponents();
    }
    
    /**
     * Initialize UI components.
     */
    private void initComponents() {
        setLayout(new BorderLayout());
        
        // Top control panel
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearButton = new JButton("Clear Parameters");
        clearButton.addActionListener((ActionEvent e) -> {
            tableModel.clear();
            parameterRiskMap.clear();
        });
        controlPanel.add(clearButton);
        
        JButton exportButton = new JButton("Export Parameters (CSV)");
        exportButton.addActionListener((ActionEvent e) -> exportParameters());
        controlPanel.add(exportButton);
        
        JButton highRiskButton = new JButton("Show High Risk Only");
        highRiskButton.addActionListener((ActionEvent e) -> filterHighRisk());
        controlPanel.add(highRiskButton);
        
        add(controlPanel, BorderLayout.NORTH);
        
        // Parameter table
        parameterTable = new JTable(tableModel);
        parameterTable.setAutoCreateRowSorter(true);
        parameterTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        parameterTable.getColumnModel().getColumn(3).setMaxWidth(100);
        
        JScrollPane scrollPane = new JScrollPane(parameterTable);
        add(scrollPane, BorderLayout.CENTER);
    }
    
    /**
     * Add a parameter to the table.
     */
    public void addParameter(Parameter parameter) {
        SwingUtilities.invokeLater(() -> {
            tableModel.addParameter(parameter);
            parameterRiskMap.put(parameter.getName(), parameter.getRiskScore());
        });
    }
    
    /**
     * Export parameters to CSV file.
     */
    private void exportParameters() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setSelectedFile(new java.io.File("parameters.csv"));
        int result = fileChooser.showSaveDialog(this);
        
        if (result == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File file = fileChooser.getSelectedFile();
                java.io.FileWriter writer = new java.io.FileWriter(file);
                
                // Write header
                writer.write("Name,Value,Type,Risk Score\n");
                
                // Write data
                for (Parameter param : tableModel.getParameters()) {
                    writer.write("\"" + escapeCsv(param.getName()) + "\",\"" + 
                            escapeCsv(param.getValue()) + "\",\"" + 
                            param.getType() + "\"," + param.getRiskScore() + "\n");
                }
                
                writer.close();
                JOptionPane.showMessageDialog(this, "Parameters exported successfully!");
            } catch (Exception e) {
                JOptionPane.showMessageDialog(this, "Error exporting parameters: " + e.getMessage(), 
                        "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Filter to show only high-risk parameters (score >= 7).
     */
    private void filterHighRisk() {
        ParameterTableModel filteredModel = new ParameterTableModel();
        for (Parameter param : tableModel.getParameters()) {
            if (param.getRiskScore() >= 7) {
                filteredModel.addParameter(param);
            }
        }
        parameterTable.setModel(filteredModel);
    }
    
    /**
     * Escape CSV special characters.
     */
    private String escapeCsv(String value) {
        if (value == null) return "";
        return value.replace("\"", "\"\"").replace("\n", " ").replace("\r", " ");
    }
    
    /**
     * Table model for parameters.
     */
    private static class ParameterTableModel extends AbstractTableModel {
        private final List<Parameter> parameters = new ArrayList<>();
        private final String[] columnNames = {"Name", "Value", "Type", "Risk Score"};
        
        public void addParameter(Parameter parameter) {
            // Check for duplicates
            for (Parameter existing : parameters) {
                if (existing.getName().equals(parameter.getName())) {
                    return;
                }
            }
            parameters.add(parameter);
            fireTableDataChanged();
        }
        
        public void clear() {
            parameters.clear();
            fireTableDataChanged();
        }
        
        public List<Parameter> getParameters() {
            return new ArrayList<>(parameters);
        }
        
        @Override
        public int getRowCount() {
            return parameters.size();
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            Parameter param = parameters.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return param.getName();
                case 1:
                    return param.getValue();
                case 2:
                    return param.getType();
                case 3:
                    return param.getRiskScore();
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
                case 3:
                    return Integer.class;
                default:
                    return String.class;
            }
        }
    }
}
