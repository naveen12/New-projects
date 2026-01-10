# BurpXcelerator

BurpXcelerator is a Burp Suite extension designed to reduce penetration testing time by automating reconnaissance, prioritization, access control testing, and reporting.

## Features

- **Core Engine**: Captures and analyzes HTTP traffic.
- **URL Relevance Engine**: Scores URLs based on their potential attack surface.
- **Smart Parameter Analyzer**: Identifies and categorizes request parameters.
- **Broken Access Control Tester**: Automates testing for broken access control vulnerabilities.
- **Integrations**: Placeholder for Nuclei and Semgrep integrations.
- **Auto PoC Generator**: Generates vulnerability reports in Markdown format.

## Compilation

To compile this extension, you will need to have the Burp Suite API files in your classpath. You can obtain these from the Burp Suite installation directory or from the official PortSwigger website.

1.  **Download the Burp Suite API**: Download the `burp-extender-api.jar` file from the PortSwigger website.
2.  **Compile the source code**:
    ```bash
    javac -cp burp-extender-api.jar -d build $(find src -name "*.java")
    ```
3.  **Package the extension**:
    ```bash
    jar -cvf BurpXcelerator.jar -C build .
    ```

## Loading into Burp Suite

1.  Open Burp Suite.
2.  Go to the "Extender" tab.
3.  Click on the "Add" button in the "Burp Extensions" section.
4.  In the "Add extension" dialog, select "Java" as the "Extension type".
5.  Click on the "Select file..." button and choose the `BurpXcelerator.jar` file.
6.  Click "Next". The extension should be loaded and a new tab named "BurpXcelerator" will appear in the main tabbed pane.
