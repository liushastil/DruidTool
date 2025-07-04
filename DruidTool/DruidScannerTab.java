package DruidTool;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.core.ByteArray; // 导入ByteArray
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONArray;
import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONException; // 导入Fastjson2的特定异常

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects; // 导入Objects工具类
import java.util.Arrays; // 导入Arrays用于清空密码
import java.util.concurrent.ConcurrentHashMap; // 用于存储session
import java.util.List;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;

public class DruidScannerTab {
    private final MontoyaApi api;
    private final JPanel mainPanel;
    private final JTextField textURL;
    private final JTextField textUserName;
    private final JPasswordField textPassWord; // 使用JPasswordField
    private final JTextArea textHeader;
    private final JTextField textProxy; // 目前未实现代理功能，但保留UI
    private final JTextArea textJDBC;
    private final JTextArea textSessions;
    private final JTextArea textSqls;
    private final JTextArea textUrls;
    private final JTextArea textSessionChanges;
    private final JButton runButton;
    private final JButton updateDataButton;
    private final JButton clearSessionButton;
    private final JLabel logs;
    private final JLabel sessionStatus;
    
    // Session存储 - 使用ConcurrentHashMap确保线程安全
    // key: baseUrl, value: cookie
    private final Map<String, String> sessionStore = new ConcurrentHashMap<>();
    // 原始URL存储 - 用于提取Druid路径
    private final Map<String, String> originalUrlStore = new ConcurrentHashMap<>();
    // 上次扫描结果存储 - 用于对比变化
    private final Map<String, String> lastScanResults = new ConcurrentHashMap<>();

    // 新增：解析用户输入URL，分离baseUrl和pathPrefix
    private static class ParsedUrl {
        String baseUrl; // 协议+主机+端口
        String pathPrefix; // 路径前缀（如 /ticket），不带末尾/
    }
    private ParsedUrl parseUserUrl(String userInput) {
        ParsedUrl result = new ParsedUrl();
        try {
            java.net.URL urlObj = new java.net.URL(userInput);
            result.baseUrl = urlObj.getProtocol() + "://" + urlObj.getHost();
            if (urlObj.getPort() > 0 && urlObj.getPort() != 80 && urlObj.getPort() != 443) {
                result.baseUrl += ":" + urlObj.getPort();
            }
            String path = urlObj.getPath();
            if (path == null || path.isEmpty() || "/".equals(path)) {
                result.pathPrefix = "";
            } else {
                result.pathPrefix = path.startsWith("/") ? path : "/" + path;
                result.pathPrefix = result.pathPrefix.replaceAll("/+$", "");
            }
        } catch (Exception e) {
            if (userInput.contains("://")) {
                result.baseUrl = userInput.substring(0, userInput.indexOf("/", 8));
                result.pathPrefix = userInput.substring(result.baseUrl.length());
            } else {
                result.baseUrl = userInput;
                result.pathPrefix = "";
            }
        }
        return result;
    }

    // 1. UI成员变量（只保留必要的）
    private JTextField jdbcSearchField = new JTextField();
    private JTextField sessionsSearchField = new JTextField();
    private JTextField sqlsSearchField = new JTextField();
    private JTextField urlsSearchField = new JTextField();
    private JTextField sessionChangesSearchField = new JTextField();
    private JTextArea addedArea = new JTextArea();
    private JTextArea removedArea = new JTextArea();
    private JTextArea unchangedArea = new JTextArea();
    private String jdbcRawContent = "";
    private String sessionsRawContent = "";
    private String sqlsRawContent = "";
    private String urlsRawContent = "";

    public DruidScannerTab(MontoyaApi api) {
        this.api = api;
        mainPanel = new JPanel(new BorderLayout());
        textURL = new JTextField(40);
        textUserName = new JTextField(20);
        textPassWord = new JPasswordField(20);
        textHeader = new JTextArea(5, 40);
        textProxy = new JTextField(20);
        textJDBC = createResultTextArea();
        textSessions = createResultTextArea();
        textSqls = createResultTextArea();
        textUrls = createResultTextArea();
        textSessionChanges = createSessionChangesArea();
        runButton = new JButton("Run");
        updateDataButton = new JButton("Update Data");
        clearSessionButton = new JButton("Clear Session");
        logs = new JLabel("Ready");
        sessionStatus = new JLabel("No session");
        sessionStatus.setForeground(Color.GRAY);
        initUI();
    }

    private void initUI() {
        JPanel inputPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // 将组件添加到输入面板
        addComponent(inputPanel, new JLabel("Target URL:"), textURL, gbc, 0);
        addComponent(inputPanel, new JLabel("Username:"), textUserName, gbc, 1);
        addComponent(inputPanel, new JLabel("Password:"), textPassWord, gbc, 2);
        addComponent(inputPanel, new JLabel("Headers:"), new JScrollPane(textHeader), gbc, 3);
        addComponent(inputPanel, new JLabel("Proxy:"), textProxy, gbc, 4); // 代理输入框

        // 将输入面板和结果面板添加到主面板
        mainPanel.add(inputPanel, BorderLayout.NORTH);

        // 添加控制面板
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlPanel.add(runButton);
        controlPanel.add(updateDataButton);
        controlPanel.add(clearSessionButton);
        controlPanel.add(logs);
        controlPanel.add(sessionStatus);
        mainPanel.add(controlPanel, BorderLayout.SOUTH);

        // 为按钮添加动作监听器
        runButton.addActionListener(e -> performScan());
        updateDataButton.addActionListener(e -> updateData());
        clearSessionButton.addActionListener(e -> clearSession());
        
        // 添加URL测试按钮
        JButton testButton = new JButton("Test URL");
        testButton.addActionListener(e -> testUrl());
        controlPanel.add(testButton);
        
        JButton exportButton = new JButton("Export Results");
        exportButton.addActionListener(e -> exportResults());
        controlPanel.add(exportButton);
        
        JButton clearHistoryButton = new JButton("Clear History");
        clearHistoryButton.addActionListener(e -> clearHistory());
        controlPanel.add(clearHistoryButton);

        // 结果区Tab
        JTabbedPane resultsPane = new JTabbedPane();
        resultsPane.addTab("JDBC Info", createTabPanel(textJDBC, jdbcSearchField, () -> jdbcRawContent));
        resultsPane.addTab("Sessions", createTabPanel(textSessions, sessionsSearchField, () -> sessionsRawContent));
        resultsPane.addTab("SQL Queries", createTabPanel(textSqls, sqlsSearchField, () -> sqlsRawContent));
        resultsPane.addTab("URIs", createTabPanel(textUrls, urlsSearchField, () -> urlsRawContent));
        resultsPane.addTab("Session Changes", createSessionChangesTab());
        mainPanel.add(resultsPane, BorderLayout.CENTER);
    }

    private JTextArea createResultTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font("Monospace", Font.PLAIN, 12));
        return area;
    }
    
    private JTextArea createSessionChangesArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setFont(new Font("Monospace", Font.PLAIN, 12));
        area.setText("Session变化对比将在这里显示...\n\n点击Update Data后会自动更新对比结果。");
        return area;
    }

    private void addComponent(JPanel panel, JLabel label, Component component, GridBagConstraints gbc, int row) {
        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(label, gbc);

        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(component, gbc);
    }

    private void performScan() {
        clearResults();
        logs.setText("Scanning...");
        runButton.setEnabled(false);
        updateDataButton.setEnabled(false);
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                String userInputUrl = textURL.getText().trim();
                if (userInputUrl.isEmpty()) {
                    SwingUtilities.invokeLater(() -> {
                        showError("Target URL cannot be empty.");
                        logs.setText("Ready");
                        runButton.setEnabled(true);
                        updateDataButton.setEnabled(true);
                    });
                    return null;
                }
                try {
                    String cookie = "";
                    ParsedUrl parsed = parseUserUrl(userInputUrl);
                    String baseUrl = parsed.baseUrl;
                    String pathPrefix = parsed.pathPrefix;
                    boolean loginRequired = !textUserName.getText().isEmpty() && textPassWord.getPassword().length > 0;
                    if (!loginRequired && sessionStore.containsKey(baseUrl)) {
                        cookie = sessionStore.get(baseUrl);
                        api.logging().logToOutput("✓ 找到保存的session: " + baseUrl + " => " + cookie);
                        if (validateSession(baseUrl, pathPrefix, cookie)) {
                            api.logging().logToOutput("✓ Session验证成功，继续使用");
                            SwingUtilities.invokeLater(() -> {
                                sessionStatus.setText("Using saved session");
                                sessionStatus.setForeground(Color.GREEN);
                            });
                        } else {
                            api.logging().logToOutput("✗ Session已过期，需要重新登录");
                            sessionStore.remove(baseUrl);
                            cookie = "";
                            SwingUtilities.invokeLater(() -> {
                                sessionStatus.setText("Session expired");
                                sessionStatus.setForeground(Color.RED);
                            });
                        }
                    } else if (loginRequired) {
                        logs.setText("Attempting login...");
                        cookie = login(userInputUrl);
                        if (cookie.isEmpty()) {
                            SwingUtilities.invokeLater(() -> {
                                showError("Login failed. Check username/password and URL.");
                                logs.setText("Scan failed.");
                                runButton.setEnabled(true);
                                updateDataButton.setEnabled(true);
                            });
                            return null;
                        }
                        // 登录成功后立即保存session并显示'Session saved'
                        sessionStore.put(baseUrl, cookie);
                        SwingUtilities.invokeLater(() -> {
                            sessionStatus.setText("Session saved");
                            sessionStatus.setForeground(Color.GREEN);
                        });
                        logs.setText("Login successful. Scanning...");
                        api.logging().logToOutput("✓ 登录成功，Session已保存，开始扫描...");
                    }
                    getResult(userInputUrl, cookie);
                } catch (Exception e) {
                    api.logging().logToError("Scan error: " + e.getMessage());
                    SwingUtilities.invokeLater(() -> {
                        showError("An unexpected error occurred during scan: " + e.getMessage());
                        logs.setText("Scan failed.");
                        runButton.setEnabled(true);
                        updateDataButton.setEnabled(true);
                    });
                }
                return null;
            }
            @Override
            protected void done() {
                runButton.setEnabled(true);
                updateDataButton.setEnabled(true);
                logs.setText("Scan completed.");
            }
        };
        worker.execute();
    }

    private void getResult(String userInputUrl, String cookie) {
        ParsedUrl parsed = parseUserUrl(userInputUrl.trim());
        String baseUrl = parsed.baseUrl;
        String pathPrefix = parsed.pathPrefix;
        
        api.logging().logToOutput("所有请求均以 " + baseUrl + pathPrefix + "/druid 为前缀");

        String webSessionPath = (pathPrefix + "/druid/websession.json").replaceAll("//+", "/");
        String webSqlPath = (pathPrefix + "/druid/sql.json").replaceAll("//+", "/");
        String webUriPath = (pathPrefix + "/druid/weburi.json").replaceAll("//+", "/");
        String webDbPath = (pathPrefix + "/druid/datasource.json").replaceAll("//+", "/");
        String basicPath = (pathPrefix + "/druid/basic.json").replaceAll("//+", "/");

        String webSessionUrl = baseUrl + webSessionPath;
        String webSqlUrl = baseUrl + webSqlPath;
        String webUriUrl = baseUrl + webUriPath;
        String webDbUrl = baseUrl + webDbPath;
        String basicUrl = baseUrl + basicPath;
        
        api.logging().logToOutput("=== 开始扫描Druid信息 ===");
        api.logging().logToOutput("目标URL: " + userInputUrl);
        api.logging().logToOutput("Druid前缀: " + baseUrl);
        api.logging().logToOutput("Session状态: " + (cookie.isEmpty() ? "无" : "已登录"));

        // 获取会话信息
        api.logging().logToOutput("\n[1/5] 正在获取会话信息...");
        api.logging().logToOutput("访问URL: " + webSessionUrl);
        HttpResponse sessionResponse = httpGet(baseUrl, webSessionPath, cookie);
        if (sessionResponse != null && sessionResponse.statusCode() == 200) {
            String sessionBody = sessionResponse.body().toString();
            api.logging().logToOutput("✓ 会话信息获取成功 (状态码: " + sessionResponse.statusCode() + ", 内容长度: " + sessionBody.length() + ")");
            String sessionData = getDruidJson(sessionBody, "SESSIONID");
            this.textSessions.setText(formatOutput("会话信息", sessionData));
            api.logging().logToOutput("会话数据: " + (sessionData.contains("No data") ? "无数据" : "已获取"));
            
            // 保存当前扫描结果并对比变化
            String currentSessions = sessionData;
            String lastSessions = lastScanResults.get("sessions");
            if (lastSessions != null) {
                compareSessionsList(lastSessions, currentSessions);
            } else {
                // 首次扫描，全部视为新增
                sessionAddedList = java.util.Arrays.asList(currentSessions.split("\n"));
                sessionRemovedList = new java.util.ArrayList<>();
                sessionUnchangedList = new java.util.ArrayList<>();
                filterSessionChanges();
            }
            lastScanResults.put("sessions", currentSessions);
            this.sessionsRawContent = formatOutput("会话信息", sessionData);
            filterOutputArea(textSessions, sessionsSearchField, sessionsRawContent);
        } else {
            String errorMsg = "Failed to retrieve sessions. Status: " + (sessionResponse != null ? sessionResponse.statusCode() : "No response");
            this.textSessions.setText(formatOutput("会话信息", errorMsg));
            api.logging().logToError("✗ 会话信息获取失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + webSessionUrl);
            api.logging().logToError("响应状态码: " + (sessionResponse != null ? sessionResponse.statusCode() : "No response"));
            if (sessionResponse != null) {
                api.logging().logToError("响应内容: " + sessionResponse.body().toString());
            }
        }

        // 获取SQL查询信息
        api.logging().logToOutput("\n[2/5] 正在获取SQL查询信息...");
        api.logging().logToOutput("访问URL: " + webSqlUrl);
        HttpResponse sqlResponse = httpGet(baseUrl, webSqlPath, cookie);
        if (sqlResponse != null && sqlResponse.statusCode() == 200) {
            String sqlBody = sqlResponse.body().toString();
            api.logging().logToOutput("✓ SQL查询信息获取成功 (状态码: " + sqlResponse.statusCode() + ", 内容长度: " + sqlBody.length() + ")");
            String sqlData = getDruidJson(sqlBody, "SQL");
            this.textSqls.setText(formatOutput("SQL查询信息", sqlData));
            api.logging().logToOutput("SQL数据: " + (sqlData.contains("No data") ? "无数据" : "已获取"));
            this.sqlsRawContent = formatOutput("SQL查询信息", sqlData);
            filterOutputArea(textSqls, sqlsSearchField, sqlsRawContent);
        } else {
            String errorMsg = "Failed to retrieve SQL queries. Status: " + (sqlResponse != null ? sqlResponse.statusCode() : "No response");
            this.textSqls.setText(formatOutput("SQL查询信息", errorMsg));
            api.logging().logToError("✗ SQL查询信息获取失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + webSqlUrl);
            api.logging().logToError("响应状态码: " + (sqlResponse != null ? sqlResponse.statusCode() : "No response"));
        }

        // 获取URI信息
        api.logging().logToOutput("\n[3/5] 正在获取URI访问信息...");
        api.logging().logToOutput("访问URL: " + webUriUrl);
        HttpResponse uriResponse = httpGet(baseUrl, webUriPath, cookie);
        if (uriResponse != null && uriResponse.statusCode() == 200) {
            String uriBody = uriResponse.body().toString();
            api.logging().logToOutput("✓ URI信息获取成功 (状态码: " + uriResponse.statusCode() + ", 内容长度: " + uriBody.length() + ")");
            String uriData = getDruidJson(uriBody, "URI");
            this.textUrls.setText(formatOutput("URI访问信息", uriData));
            api.logging().logToOutput("URI数据: " + (uriData.contains("No data") ? "无数据" : "已获取"));
            this.urlsRawContent = formatOutput("URI访问信息", uriData);
            filterOutputArea(textUrls, urlsSearchField, urlsRawContent);
        } else {
            String errorMsg = "Failed to retrieve URIs. Status: " + (uriResponse != null ? uriResponse.statusCode() : "No response");
            this.textUrls.setText(formatOutput("URI访问信息", errorMsg));
            api.logging().logToError("✗ URI信息获取失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + webUriUrl);
            api.logging().logToError("响应状态码: " + (uriResponse != null ? uriResponse.statusCode() : "No response"));
        }

        // 获取JDBC和基本信息
        api.logging().logToOutput("\n[4/5] 正在获取JDBC数据源信息...");
        api.logging().logToOutput("访问URL: " + webDbUrl);
        HttpResponse webDbResponse = httpGet(baseUrl, webDbPath, cookie);
        
        api.logging().logToOutput("\n[5/5] 正在获取系统基本信息...");
        api.logging().logToOutput("访问URL: " + basicUrl);
        HttpResponse basicResponse = httpGet(baseUrl, basicPath, cookie);

        Map<String, String> info = new HashMap<>();
        StringBuilder jdbcOutput = new StringBuilder();
        
        // 只有当响应成功且状态码为200时才尝试解析JSON
        if (webDbResponse != null && webDbResponse.statusCode() == 200) {
            String webDbResBody = webDbResponse.body().toString();
            api.logging().logToOutput("✓ JDBC信息获取成功 (状态码: " + webDbResponse.statusCode() + ", 内容长度: " + webDbResBody.length() + ")");
            String userName = getDruidJson(webDbResBody, "UserName");
            String jdbcUrl = getDruidJson(webDbResBody, "URL");
            info.put("userName", userName);
            info.put("jdbcUrl", jdbcUrl);
            jdbcOutput.append("数据库用户名: ").append(userName).append("\n");
            jdbcOutput.append("JDBC连接URL: ").append(jdbcUrl).append("\n");
        } else {
            String errorMsg = "Failed to retrieve JDBC DataSource info. Status: " + (webDbResponse != null ? webDbResponse.statusCode() : "No response");
            jdbcOutput.append(errorMsg);
            api.logging().logToError("✗ JDBC信息获取失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + webDbUrl);
            api.logging().logToError("响应状态码: " + (webDbResponse != null ? webDbResponse.statusCode() : "No response"));
        }

        if (basicResponse != null && basicResponse.statusCode() == 200) {
            String basicResBody = basicResponse.body().toString();
            api.logging().logToOutput("✓ 基本信息获取成功 (状态码: " + basicResponse.statusCode() + ", 内容长度: " + basicResBody.length() + ")");
            String javaClassPath = getDruidJson(basicResBody, "JavaClassPath");
            String javaVMName = getDruidJson(basicResBody, "JavaVMName");
            String javaVersion = getDruidJson(basicResBody, "JavaVersion");
            info.put("javaClassPath", javaClassPath);
            info.put("javaVMName", javaVMName);
            info.put("javaVersion", javaVersion);
            jdbcOutput.append("Java类路径: ").append(javaClassPath).append("\n");
            jdbcOutput.append("Java虚拟机名称: ").append(javaVMName).append("\n");
            jdbcOutput.append("Java版本: ").append(javaVersion).append("\n");
        } else {
            String errorMsg = "Failed to retrieve Basic System info. Status: " + (basicResponse != null ? basicResponse.statusCode() : "No response");
            jdbcOutput.append(errorMsg);
            api.logging().logToError("✗ 基本信息获取失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + basicUrl);
            api.logging().logToError("响应状态码: " + (basicResponse != null ? basicResponse.statusCode() : "No response"));
        }

        // 设置格式化的JDBC输出
        this.textJDBC.setText(formatOutput("JDBC和系统信息", jdbcOutput.toString()));
        this.jdbcRawContent = jdbcOutput.toString();
        filterOutputArea(textJDBC, jdbcSearchField, jdbcRawContent);
        
        api.logging().logToOutput("\n=== 扫描完成 ===");
        api.logging().logToOutput("所有Druid信息扫描已完成");
    }

    private HttpResponse httpGet(String baseUrl, String path, String cookie) {
        HttpService service = HttpService.httpService(baseUrl);
        Map<String, String> headers = parseHeaders(cookie);
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("GET ").append(path).append(" HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(service.host());
        if (service.port() != 80 && service.port() != 443) {
            requestBuilder.append(":" + service.port());
        }
        requestBuilder.append("\r\n");
        requestBuilder.append("Connection: close\r\n");
        requestBuilder.append("Sec-Ch-Ua-Platform: \"Windows\"\r\n");
        requestBuilder.append("X-Requested-With: XMLHttpRequest\r\n");
        requestBuilder.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36\r\n");
        requestBuilder.append("Accept: text/plain, */*; q=0.01\r\n");
        requestBuilder.append("Sec-Ch-Ua: \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"\r\n");
        requestBuilder.append("Sec-Ch-Ua-Mobile: ?0\r\n");
        requestBuilder.append("Sec-Fetch-Site: same-origin\r\n");
        requestBuilder.append("Sec-Fetch-Mode: cors\r\n");
        requestBuilder.append("Sec-Fetch-Dest: empty\r\n");
        requestBuilder.append("Accept-Encoding: gzip, deflate, br\r\n");
        requestBuilder.append("Accept-Language: zh-CN,zh;q=0.9\r\n");
        requestBuilder.append("Dnt: 1\r\n");
        requestBuilder.append("Sec-Gpc: 1\r\n");
        requestBuilder.append("Cache-Control: no-cache\r\n");
        
        // 添加自定义头部
        for (Map.Entry<String, String> header : headers.entrySet()) {
            requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        requestBuilder.append("\r\n");
        
        // 记录请求内容用于调试
        api.logging().logToOutput("[HTTP] 请求路径: " + path);
        api.logging().logToOutput("[HTTP] Host: " + service.host() + (service.port() != 80 && service.port() != 443 ? (":" + service.port()) : ""));
        api.logging().logToOutput("[HTTP] 请求头Cookie: " + headers.getOrDefault("Cookie", ""));
        
        HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBuilder.toString().getBytes()));
        HttpRequestResponse response = api.http().sendRequest(request);

        if (response != null && response.response() != null) {
            api.logging().logToOutput("收到响应，状态码: " + response.response().statusCode() + " (URL: " + baseUrl + path + ")");
            if (response.response().statusCode() == 404) {
                api.logging().logToError("404错误 - 详细错误信息:");
                api.logging().logToError("完整访问路径: " + baseUrl + path);
                api.logging().logToError("响应状态码: " + response.response().statusCode());
            }
            return response.response();
        } else {
            api.logging().logToError("HTTP请求失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + baseUrl + path);
            api.logging().logToError("未收到响应或响应为空");
            return null; // 指示失败
        }
    }

    private String login(String userInputUrl) {
        ParsedUrl parsed = parseUserUrl(userInputUrl);
        String baseUrl = parsed.baseUrl;
        String pathPrefix = parsed.pathPrefix;
        String loginPath = (pathPrefix + "/druid/submitLogin").replaceAll("//+", "/");
        String loginUrl = baseUrl + loginPath;
        api.logging().logToOutput("正在尝试登录: " + loginUrl);
        HttpService service = HttpService.httpService(baseUrl);
        char[] passwordChars = textPassWord.getPassword();
        StringBuilder passwordBuilder = new StringBuilder();
        for (char c : passwordChars) passwordBuilder.append(c);
        String requestBody = String.format("loginUsername=%s&loginPassword=%s",
                textUserName.getText(), passwordBuilder.toString());
        passwordBuilder.setLength(0); // 清空密码
        Arrays.fill(passwordChars, ' ');
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append("POST ").append(loginPath).append(" HTTP/1.1\r\n");
        requestBuilder.append("Host: ").append(service.host());
        if (service.port() != 80 && service.port() != 443) {
            requestBuilder.append(":" + service.port());
        }
        requestBuilder.append("\r\n");
        requestBuilder.append("Sec-Ch-Ua-Platform: \"Windows\"\r\n");
        requestBuilder.append("X-Requested-With: XMLHttpRequest\r\n");
        requestBuilder.append("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36\r\n");
        requestBuilder.append("Accept: text/plain, */*; q=0.01\r\n");
        requestBuilder.append("Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n");
        requestBuilder.append("Sec-Ch-Ua: \"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"138\", \"Google Chrome\";v=\"138\"\r\n");
        requestBuilder.append("Sec-Ch-Ua-Mobile: ?0\r\n");
        requestBuilder.append("Sec-Fetch-Site: same-origin\r\n");
        requestBuilder.append("Sec-Fetch-Mode: cors\r\n");
        requestBuilder.append("Sec-Fetch-Dest: empty\r\n");
        requestBuilder.append("Referer: ").append(baseUrl).append(loginPath.replace("submitLogin", "login.html")).append("\r\n");
        requestBuilder.append("Accept-Encoding: gzip, deflate, br\r\n");
        requestBuilder.append("Accept-Language: zh-CN,zh;q=0.9\r\n");
        requestBuilder.append("Dnt: 1\r\n");
        requestBuilder.append("Sec-Gpc: 1\r\n");
        requestBuilder.append("Priority: u=1, i\r\n");
        requestBuilder.append("Connection: close\r\n");
        requestBuilder.append("Content-Length: ").append(requestBody.getBytes().length).append("\r\n");
        Map<String, String> customHeaders = parseHeaders("");
        for (Map.Entry<String, String> header : customHeaders.entrySet()) {
            requestBuilder.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }
        requestBuilder.append("\r\n");
        requestBuilder.append(requestBody);
        api.logging().logToOutput("完整请求内容:");
        api.logging().logToOutput(requestBuilder.toString());
        HttpRequest request = HttpRequest.httpRequest(service, ByteArray.byteArray(requestBuilder.toString().getBytes()));
        HttpRequestResponse response = api.http().sendRequest(request);
        if (response != null && response.response() != null) {
            if (response.response().statusCode() == 302 || response.response().statusCode() == 200) {
                List<String> setCookies = response.response().headers().stream()
                    .filter(header -> header.name().equalsIgnoreCase("Set-Cookie"))
                    .map(header -> header.value().split(";", 2)[0])
                    .collect(java.util.stream.Collectors.toList());
                api.logging().logToOutput("[LOGIN] Set-Cookie头: " + setCookies);
                String cookie = String.join("; ", setCookies);
                api.logging().logToOutput("[LOGIN] 拼接后的Cookie: " + cookie);
                api.logging().logToOutput("[LOGIN] 保存到sessionStore: key=" + baseUrl + ", value=" + cookie);
                if (!cookie.isEmpty()) {
                    sessionStore.put(baseUrl, cookie);
                    return cookie;
                } else {
                    api.logging().logToError("登录响应成功但未找到Cookie");
                    api.logging().logToError("完整访问路径: " + loginUrl);
                    api.logging().logToError("响应状态码: " + response.response().statusCode());
                    api.logging().logToError("响应头: " + response.response().headers());
                    return "";
                }
            } else {
                api.logging().logToError("登录失败 - 详细错误信息:");
                api.logging().logToError("完整访问路径: " + loginUrl);
                api.logging().logToError("响应状态码: " + response.response().statusCode());
                api.logging().logToError("响应内容: " + response.response().body().toString());
                return "";
            }
        } else {
            api.logging().logToError("登录请求失败 - 详细错误信息:");
            api.logging().logToError("完整访问路径: " + loginUrl);
            api.logging().logToError("未收到响应或响应为空");
            return "";
        }
    }

    private Map<String, String> parseHeaders(String cookie) {
        Map<String, String> headers = new HashMap<>();
        if (!cookie.isEmpty()) {
            headers.put("Cookie", cookie);
        }
        String[] lines = textHeader.getText().split("\\r?\\n");
        for (String line : lines) {
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    headers.put(parts[0].trim(), parts[1].trim());
                }
            }
        }
        return headers;
    }

    private String getDruidJson(String body, String fieldName) {
        if (body == null || body.isEmpty()) {
            api.logging().logToError("响应体为空");
            return "No data received.\n";
        }
        api.logging().logToOutput("原始响应内容 (字段: " + fieldName + "):");
        api.logging().logToOutput(body);
        try {
            Object json = JSON.parse(body);
            List<String> results = new ArrayList<>();
            findJsonFields(json, fieldName, "", results);
            if (!results.isEmpty()) {
                return String.join("\n", results);
            }
        } catch (JSONException e) {
            api.logging().logToError("JSON解析错误 (字段: " + fieldName + "): " + e.getMessage());
            api.logging().logToError("响应内容: " + body);
            return "Error parsing JSON for " + fieldName + ": " + e.getMessage() + "\n";
        } catch (Exception e) {
            api.logging().logToError("获取Druid JSON时发生通用错误 (字段: " + fieldName + "): " + e.getMessage());
            api.logging().logToError("响应内容: " + body);
            return "General error when getting Druid JSON for " + fieldName + ": " + e.getMessage() + "\n";
        }
        return "No data found for field: " + fieldName + "\n";
    }
    
    private void findJsonFields(Object node, String targetField, String currentPath, List<String> results) {
        if (node instanceof JSONObject) {
            JSONObject obj = (JSONObject) node;
            for (String key : obj.keySet()) {
                Object value = obj.get(key);
                String newPath = currentPath.isEmpty() ? key : currentPath + "." + key;
                if (key.equalsIgnoreCase(targetField)) {
                    results.add(Objects.toString(value, ""));
                }
                findJsonFields(value, targetField, newPath, results);
            }
        } else if (node instanceof JSONArray) {
            JSONArray array = (JSONArray) node;
            for (int i = 0; i < array.size(); i++) {
                findJsonFields(array.get(i), targetField, currentPath + "[" + i + "]", results);
            }
        }
    }

    private void clearResults() {
        textJDBC.setText("");
        textSessions.setText("");
        textSqls.setText("");
        textUrls.setText("");
        textSessionChanges.setText("Session变化对比将在这里显示...\n\n点击Update Data后会自动更新对比结果。");
    }

    private String getBaseUrl(String url) {
        try {
            java.net.URL urlObj = new java.net.URL(url);
            String protocol = urlObj.getProtocol();
            String host = urlObj.getHost();
            int port = urlObj.getPort();
            
            StringBuilder baseUrl = new StringBuilder();
            baseUrl.append(protocol).append("://").append(host);
            
            if (port != -1) {
                baseUrl.append(":").append(port);
            }
            
            // 不保留原始路径，只返回协议+主机+端口
            // 因为Druid路径会在后续步骤中处理
            
            return baseUrl.toString();
        } catch (Exception e) {
            api.logging().logToError("解析URL失败: " + url + ", 错误: " + e.getMessage());
            return url; // 如果解析失败，返回原URL
        }
    }

    private void testUrl() {
        String url = textURL.getText().trim();
        if (url.isEmpty()) {
            showError("请输入要测试的URL");
            return;
        }
        
        // 确保URL格式正确
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
            textURL.setText(url);
        }
        
        final String finalUrl = url;
        logs.setText("测试URL中...");
        
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    ParsedUrl parsed = parseUserUrl(finalUrl.trim());
                    String baseUrl = parsed.baseUrl;
                    String pathPrefix = parsed.pathPrefix;
                    String testPath = (pathPrefix + "/druid/index.html").replaceAll("//+", "/");
                    String testUrl = baseUrl + testPath;
                    HttpResponse response = httpGet(baseUrl, testPath, "");
                    if (response != null) {
                        api.logging().logToOutput("测试URL " + testUrl + " 响应码: " + response.statusCode());
                        SwingUtilities.invokeLater(() -> logs.setText("测试完成，响应码: " + response.statusCode()));
                    } else {
                        api.logging().logToOutput("测试URL " + testUrl + " 无响应");
                        SwingUtilities.invokeLater(() -> logs.setText("测试失败，无响应"));
                    }
                } catch (Exception e) {
                    api.logging().logToError("测试URL异常: " + e.getMessage());
                    SwingUtilities.invokeLater(() -> logs.setText("测试异常: " + e.getMessage()));
                }
                return null;
            }
        };
        worker.execute();
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(mainPanel, message, "Error", JOptionPane.ERROR_MESSAGE);
    }
    
    private void clearSession() {
        String url = textURL.getText().trim();
        if (!url.isEmpty()) {
            String baseUrl = getBaseUrl(url);
            sessionStore.remove(baseUrl);
            originalUrlStore.remove(baseUrl);
            api.logging().logToOutput("✓ Session已清除: " + baseUrl);
            SwingUtilities.invokeLater(() -> {
                sessionStatus.setText("Session cleared");
                sessionStatus.setForeground(Color.ORANGE);
            });
        } else {
            // 清除所有session
            sessionStore.clear();
            originalUrlStore.clear();
            api.logging().logToOutput("✓ 所有Session已清除");
            SwingUtilities.invokeLater(() -> {
                sessionStatus.setText("All sessions cleared");
                sessionStatus.setForeground(Color.ORANGE);
            });
        }
    }
    
    private void updateData() {
        updateDataButton.setEnabled(false);
        SwingWorker<Void, Void> worker = new SwingWorker<>() {
            @Override
            protected Void doInBackground() {
                try {
                    String userInputUrl = textURL.getText().trim();
                    ParsedUrl parsed = parseUserUrl(userInputUrl);
                    String baseUrl = parsed.baseUrl;
                    String pathPrefix = parsed.pathPrefix;
                    String cookie = sessionStore.get(baseUrl);
                    if (cookie == null || cookie.isEmpty()) {
                        SwingUtilities.invokeLater(() -> {
                            showError("No saved session. Please login first.");
                            sessionStatus.setText("No session");
                            sessionStatus.setForeground(Color.RED);
                            updateDataButton.setEnabled(true);
                        });
                        return null;
                    }
                    // 先判断session是否有效
                    if (!validateSession(baseUrl, pathPrefix, cookie)) {
                        SwingUtilities.invokeLater(() -> {
                            showError("Session expired. Please login again.");
                            sessionStatus.setText("Session expired");
                            sessionStatus.setForeground(Color.RED);
                            updateDataButton.setEnabled(true);
                        });
                        sessionStore.remove(baseUrl);
                        return null;
                    }
                    api.logging().logToOutput("=== 开始更新Druid数据 ===");
                    api.logging().logToOutput("使用保存的session: " + baseUrl);
                    getResult(userInputUrl, cookie);
                    SwingUtilities.invokeLater(() -> {
                        logs.setText("Data updated successfully");
                        updateDataButton.setEnabled(true);
                        sessionStatus.setText("Data updated");
                        sessionStatus.setForeground(Color.GREEN);
                    });
                } catch (Exception e) {
                    api.logging().logToError("更新数据时发生错误: " + e.getMessage());
                    SwingUtilities.invokeLater(() -> {
                        showError("更新数据时发生错误: " + e.getMessage());
                        logs.setText("Update failed");
                        updateDataButton.setEnabled(true);
                    });
                }
                return null;
            }
        };
        worker.execute();
    }
    
    private String formatOutput(String title, String content) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(title).append(" ===\n");
        sb.append("扫描时间: ").append(java.time.LocalDateTime.now()).append("\n");
        sb.append("状态: ").append(content.contains("Failed") || content.contains("No data") ? "失败" : "成功").append("\n");
        sb.append("数据内容:\n");
        sb.append(content);
        sb.append("\n=== 扫描完成 ===\n");
        return sb.toString();
    }
    
    private boolean validateSession(String baseUrl, String pathPrefix, String cookie) {
        String probePath = (pathPrefix + "/druid/basic.json").replaceAll("//+", "/");
        HttpResponse response = httpGet(baseUrl, probePath, cookie);
        if (response != null && response.statusCode() == 200) {
            try {
                JSONObject json = JSON.parseObject(response.body().toString());
                if (json.containsKey("ResultCode") && json.getInteger("ResultCode") == 1 && json.containsKey("Content")) {
                    String contentStr = json.get("Content").toString();
                    return !contentStr.isEmpty();
                }
            } catch (Exception e) {
                return false;
            }
        }
        // 302 或其他都视为无效
        return false;
    }
    
    // 3. compareSessions方法返回三个List<String>
    private void compareSessionsList(String lastSessions, String currentSessions) {
        java.util.Set<String> lastSet = new java.util.LinkedHashSet<>();
        java.util.Set<String> currentSet = new java.util.LinkedHashSet<>();
        if (lastSessions != null && !lastSessions.contains("No data") && !lastSessions.contains("Failed")) {
            String[] lastLines = lastSessions.split("\n");
            for (String line : lastLines) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("===") && !line.startsWith("扫描时间") &&
                    !line.startsWith("状态") && !line.startsWith("数据内容") && !line.startsWith("扫描完成")) {
                    lastSet.add(line);
                }
            }
        }
        if (currentSessions != null && !currentSessions.contains("No data") && !currentSessions.contains("Failed")) {
            String[] currentLines = currentSessions.split("\n");
            for (String line : currentLines) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("===") && !line.startsWith("扫描时间") &&
                    !line.startsWith("状态") && !line.startsWith("数据内容") && !line.startsWith("扫描完成")) {
                    currentSet.add(line);
                }
            }
        }
        java.util.List<String> added = new java.util.ArrayList<>();
        java.util.List<String> removed = new java.util.ArrayList<>();
        java.util.List<String> unchanged = new java.util.ArrayList<>();
        for (String s : currentSet) if (!lastSet.contains(s)) added.add(s);
        for (String s : lastSet) if (!currentSet.contains(s)) removed.add(s);
        for (String s : lastSet) if (currentSet.contains(s)) unchanged.add(s);
        // 保存到成员变量，供过滤用
        this.sessionAddedList = added;
        this.sessionRemovedList = removed;
        this.sessionUnchangedList = unchanged;
        filterSessionChanges();
    }
    // 4. 过滤和刷新显示
    private java.util.List<String> sessionAddedList = new java.util.ArrayList<>();
    private java.util.List<String> sessionRemovedList = new java.util.ArrayList<>();
    private java.util.List<String> sessionUnchangedList = new java.util.ArrayList<>();
    private void filterSessionChanges() {
        String keyword = sessionChangesSearchField.getText().trim().toLowerCase();
        addedArea.setText(sessionAddedList.stream().filter(s -> s.toLowerCase().contains(keyword)).collect(java.util.stream.Collectors.joining("\n")));
        removedArea.setText(sessionRemovedList.stream().filter(s -> s.toLowerCase().contains(keyword)).collect(java.util.stream.Collectors.joining("\n")));
        unchangedArea.setText(sessionUnchangedList.stream().filter(s -> s.toLowerCase().contains(keyword)).collect(java.util.stream.Collectors.joining("\n")));
    }
    
    private void clearHistory() {
        lastScanResults.clear();
        textSessionChanges.setText("历史数据已清除。\n\n下次扫描将作为新的基准数据进行对比。");
        api.logging().logToOutput("✓ 历史数据已清除");
        JOptionPane.showMessageDialog(mainPanel, "历史数据已清除！\n下次扫描将作为新的基准数据进行对比。", "清除成功", JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void exportResults() {
        try {
            JFileChooser fileChooser = new JFileChooser();
            fileChooser.setDialogTitle("导出扫描结果");
            fileChooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("文本文件 (*.txt)", "txt"));
            
            if (fileChooser.showSaveDialog(mainPanel) == JFileChooser.APPROVE_OPTION) {
                java.io.File file = fileChooser.getSelectedFile();
                if (!file.getName().toLowerCase().endsWith(".txt")) {
                    file = new java.io.File(file.getAbsolutePath() + ".txt");
                }
                
                StringBuilder content = new StringBuilder();
                content.append("=== Druid Scanner 扫描结果 ===\n");
                content.append("扫描时间: ").append(java.time.LocalDateTime.now()).append("\n");
                content.append("目标URL: ").append(textURL.getText()).append("\n\n");
                
                content.append("=== JDBC和系统信息 ===\n");
                content.append(textJDBC.getText()).append("\n\n");
                
                content.append("=== 会话信息 ===\n");
                content.append(textSessions.getText()).append("\n\n");
                
                content.append("=== SQL查询信息 ===\n");
                content.append(textSqls.getText()).append("\n\n");
                
                content.append("=== URI访问信息 ===\n");
                content.append(textUrls.getText()).append("\n");
                
                java.io.FileWriter writer = new java.io.FileWriter(file);
                writer.write(content.toString());
                writer.close();
                
                api.logging().logToOutput("✓ 扫描结果已导出到: " + file.getAbsolutePath());
                JOptionPane.showMessageDialog(mainPanel, "扫描结果已成功导出到:\n" + file.getAbsolutePath(), "导出成功", JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception e) {
            api.logging().logToError("导出失败: " + e.getMessage());
            JOptionPane.showMessageDialog(mainPanel, "导出失败: " + e.getMessage(), "导出错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private JPanel createTabPanel(JTextArea area, JTextField searchField, java.util.function.Supplier<String> rawContentSupplier) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(new JScrollPane(area), BorderLayout.CENTER);
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.add(new JLabel("搜索："), BorderLayout.WEST);
        searchPanel.add(searchField, BorderLayout.CENTER);
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterOutputArea(area, searchField, rawContentSupplier.get()); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterOutputArea(area, searchField, rawContentSupplier.get()); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filterOutputArea(area, searchField, rawContentSupplier.get()); }
        });
        panel.add(searchPanel, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel createSessionChangesTab() {
        JPanel sessionChangesPanel = new JPanel(new GridLayout(1, 3, 10, 0));
        addedArea.setEditable(false);
        removedArea.setEditable(false);
        unchangedArea.setEditable(false);
        addedArea.setBorder(BorderFactory.createTitledBorder("新增的Session"));
        removedArea.setBorder(BorderFactory.createTitledBorder("删除的Session"));
        unchangedArea.setBorder(BorderFactory.createTitledBorder("未变的Session"));
        sessionChangesPanel.add(new JScrollPane(addedArea));
        sessionChangesPanel.add(new JScrollPane(removedArea));
        sessionChangesPanel.add(new JScrollPane(unchangedArea));
        sessionChangesSearchField.setToolTipText("搜索Session变化内容，支持实时过滤");
        sessionChangesSearchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filterSessionChanges(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filterSessionChanges(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filterSessionChanges(); }
        });
        JPanel searchPanel = new JPanel(new BorderLayout());
        searchPanel.add(new JLabel("搜索："), BorderLayout.WEST);
        searchPanel.add(sessionChangesSearchField, BorderLayout.CENTER);
        JPanel tabPanel = new JPanel(new BorderLayout());
        tabPanel.add(sessionChangesPanel, BorderLayout.CENTER);
        tabPanel.add(searchPanel, BorderLayout.SOUTH);
        return tabPanel;
    }

    private void filterOutputArea(JTextArea area, JTextField searchField, String rawContent) {
        String keyword = searchField.getText().trim().toLowerCase();
        if (keyword.isEmpty()) {
            area.setText(rawContent);
        } else {
            StringBuilder filtered = new StringBuilder();
            for (String line : rawContent.split("\n")) {
                if (line.toLowerCase().contains(keyword)) {
                    filtered.append(line).append("\n");
                }
            }
            area.setText(filtered.toString());
        }
    }

    public Component getUiComponent() {
        return mainPanel;
    }
}