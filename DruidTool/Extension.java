package DruidTool;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import SessionMonitor.SessionMonitorTab;

public class Extension implements BurpExtension {
    private MontoyaApi api;
    private DruidScannerTab scannerTab;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Druid Scanner");

        // Initialize scanner tab in EDT
        SwingUtilities.invokeLater(() -> {
            scannerTab = new DruidScannerTab(api);
            api.userInterface().registerSuiteTab("Druid Scanner", scannerTab.getUiComponent());
            // 集成SessionMonitorTab
            SessionMonitorTab sessionMonitorTab = new SessionMonitorTab();
            api.userInterface().registerSuiteTab("Session Monitor", sessionMonitorTab.getUiComponent());
        });

        api.logging().logToOutput("Druid Scanner loaded successfully!");
    }
}