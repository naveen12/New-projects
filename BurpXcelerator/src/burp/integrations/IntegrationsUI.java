package burp.integrations;

import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;

public class IntegrationsUI extends JPanel {

    public IntegrationsUI() {
        initComponents();
    }

    private void initComponents() {
        setLayout(new BorderLayout());

        JButton exportNucleiButton = new JButton("Export URLs for Nuclei");
        exportNucleiButton.addActionListener(e -> showNotImplementedMessage());

        JButton scanSemgrepButton = new JButton("Scan JS/API with Semgrep");
        scanSemgrepButton.addActionListener(e -> showNotImplementedMessage());

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonPanel.add(exportNucleiButton);
        buttonPanel.add(scanSemgrepButton);

        add(buttonPanel, BorderLayout.NORTH);
    }

    private void showNotImplementedMessage() {
        JOptionPane.showMessageDialog(this, "This functionality is not implemented in this version.", "Not Implemented", JOptionPane.INFORMATION_MESSAGE);
    }
}
