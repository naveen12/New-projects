package burp.parameters;

import burp.IBurpExtenderCallbacks;
import burp.core.CoreEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.util.ArrayList;
import java.util.List;

public class ParameterAnalyzerUI extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private JTable parameterTable;
    private DefaultTableModel parameterTableModel;
    private TableRowSorter<DefaultTableModel> sorter;
    private List<Parameter> parameters = new ArrayList<>();

    public ParameterAnalyzerUI(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        // Table to display parameters
        parameterTableModel = new DefaultTableModel(new Object[]{"Name", "Value", "Type", "Risk Score"}, 0);
        parameterTable = new JTable(parameterTableModel);
        sorter = new TableRowSorter<>(parameterTableModel);
        parameterTable.setRowSorter(sorter);

        JScrollPane scrollPane = new JScrollPane(parameterTable);
        add(scrollPane, BorderLayout.CENTER);
    }

    public void addParameter(Parameter parameter) {
        SwingUtilities.invokeLater(() -> {
            parameters.add(parameter);
            parameterTableModel.addRow(new Object[]{parameter.getName(), parameter.getValue(), parameter.getType(), parameter.getRiskScore()});
        });
    }
}
