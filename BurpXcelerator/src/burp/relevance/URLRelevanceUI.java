package burp.relevance;

import burp.IBurpExtenderCallbacks;
import burp.core.CoreEngine;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class URLRelevanceUI extends JPanel {
    private final IBurpExtenderCallbacks callbacks;
    private final CoreEngine coreEngine;
    private JTable urlTable;
    private DefaultTableModel urlTableModel;
    private TableRowSorter<DefaultTableModel> sorter;
    private JCheckBox showOnlyAttackableUrlsCheckBox;
    private static final int SCORE_THRESHOLD = 5;

    public URLRelevanceUI(IBurpExtenderCallbacks callbacks, CoreEngine coreEngine) {
        this.callbacks = callbacks;
        this.coreEngine = coreEngine;
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        // Table to display URLs and scores
        urlTableModel = new DefaultTableModel(new Object[]{"URL", "Score"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 1) {
                    return Integer.class;
                }
                return String.class;
            }
        };
        urlTable = new JTable(urlTableModel);
        sorter = new TableRowSorter<>(urlTableModel);
        urlTable.setRowSorter(sorter);

        JScrollPane scrollPane = new JScrollPane(urlTable);

        // Checkbox to filter URLs
        showOnlyAttackableUrlsCheckBox = new JCheckBox("Show only attackable URLs (score > " + SCORE_THRESHOLD + ")");
        showOnlyAttackableUrlsCheckBox.addActionListener(e -> filterURLs());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.add(showOnlyAttackableUrlsCheckBox);

        add(topPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
    }

    private void filterURLs() {
        if (showOnlyAttackableUrlsCheckBox.isSelected()) {
            sorter.setRowFilter(new RowFilter<DefaultTableModel, Integer>() {
                @Override
                public boolean include(Entry<? extends DefaultTableModel, ? extends Integer> entry) {
                    int score = (int) entry.getValue(1);
                    return score > SCORE_THRESHOLD;
                }
            });
        } else {
            sorter.setRowFilter(null);
        }
    }

    public void addURL(String url, int score) {
        SwingUtilities.invokeLater(() -> {
            urlTableModel.addRow(new Object[]{url, score});
        });
    }
}
