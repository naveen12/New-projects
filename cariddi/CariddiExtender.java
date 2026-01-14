package burp;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;

/**
 * Cariddi - Burp Suite Extension
 * A comprehensive endpoint, secrets, and API discovery tool integrated with Burp Suite
 * Scans URLs for endpoints, secrets, API keys, file extensions, tokens and more
 */
public class CariddiExtender implements IBurpExtender {
    private IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private PrintWriter stderr;
    private CariddiUI ui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Set extension name
        callbacks.setExtensionName("Cariddi - Advanced Endpoint Scanner");

        try {
            // Initialize UI
            SwingUtilities.invokeLater(() -> {
                ui = new CariddiUI(callbacks, stdout, stderr);
                callbacks.addSuiteTab(new CariddiTab(ui));
            });

            stdout.println("[*] Cariddi extension loaded successfully!");
            stdout.println("[*] Cariddi - Take a list of URLs, crawl and scan for endpoints, secrets, API keys, file extensions, tokens and more");
        } catch (Exception e) {
            stderr.println("[!] Error loading Cariddi extension: " + e.getMessage());
            e.printStackTrace(stderr);
        }
    }
}

/**
 * Tab implementation for Burp Suite
 */
class CariddiTab implements ITab {
    private CariddiUI ui;

    public CariddiTab(CariddiUI ui) {
        this.ui = ui;
    }

    @Override
    public String getTabCaption() {
        return "Cariddi";
    }

    @Override
    public Component getUiComponent() {
        return ui.getMainPanel();
    }
}
