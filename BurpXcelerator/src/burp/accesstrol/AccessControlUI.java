package burp.accesstrol;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.BorderLayout;

public class AccessControlUI extends JPanel {
    private JTable resultsTable;
    private DefaultTableModel resultsTableModel;

    public AccessControlUI() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        resultsTableModel = new DefaultTableModel(new Object[]{"URL", "Original Status", "Modified Status", "Original Length", "Modified Length", "Result"}, 0);
        resultsTable = new JTable(resultsTableModel);
        JScrollPane scrollPane = new JScrollPane(resultsTable);

        add(scrollPane, BorderLayout.CENTER);
    }

    public void addTestResult(String url, int originalStatus, int modifiedStatus, int originalLength, int modifiedLength, String result) {
        SwingUtilities.invokeLater(() -> {
            resultsTableModel.addRow(new Object[]{url, originalStatus, modifiedStatus, originalLength, modifiedLength, result});
        });
    }
}
