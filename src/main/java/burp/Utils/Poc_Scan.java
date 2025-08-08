package burp.Utils;

import burp.*;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Poc_Scan {
    // 去重
    private static final Set<String> scannedHosts = ConcurrentHashMap.newKeySet();

    // POC 列表
    private static final List<String> BASE_POC_LIST = Arrays.asList(
            "GET / HTTP/1.1",
            "GET /?acl HTTP/1.1",
            "GET /?policy HTTP/1.1",
            "PUT /123.txt HTTP/1.1",
            "PUT /123.png HTTP/1.1"
    );

    private static final String HOST_HEADER = "\r\nHost: ";
    private static final String USER_AGENT_HEADER = "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36";
    private static final String SEC_CH_UA_PLATFORM_HEADER = "\r\nSec-Ch-Ua-Platform: \"Windows\"";
    private static final String CONNECTION_HEADER = "\r\nConnection: keep-alive";

    // 云服务提供商常量
    private static final String CLOUD_HUAWEI = "Cloud_HuaWei";
    private static final String CLOUD_TENCENT = "Cloud_TengXun";

    // 定义需要处理的扩展名列表
    private static final String[] TARGET_EXTENSIONS = {".txt", ".js", ".json", ".png", ".jpg", ".pdf", ".zip"};
    private static final String REGEX = ".*(" + String.join("|", TARGET_EXTENSIONS) + ")$";
    private static final Pattern TARGET_EXTENSION_PATTERN = Pattern.compile(REGEX, Pattern.CASE_INSENSITIVE);
    
    // 用于存储路径的ThreadLocal变量，避免线程安全问题
    private static final ThreadLocal<List<String>> pathsHolder = new ThreadLocal<List<String>>() {
        @Override
        protected List<String> initialValue() {
            return new ArrayList<>();
        }
    };

    /**
     * 被动扫描方法，基于代理流量进行漏洞检测
     */
    public static List<RequestResponseWrapper> buildHttpServiceFromUrl(
            IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            HashMap<String, ArrayList<String>> couldHashMap,
            IHttpRequestResponse messageInfo,
            String fullUrl) {

        List<RequestResponseWrapper> results = new ArrayList<>();
        List<String> currentPocList = new ArrayList<>(BASE_POC_LIST);
        String modifiedUrl = null;
        List<String> paths = pathsHolder.get();
        paths.clear(); // 清空之前的数据

        // 解析完整URL
        String basePath = "/"; // 默认基础路径
        boolean isTargetFileUrl = false; // 标记是否为文件URL
        String hostName = "";
        int port = 443;
        boolean useHttps = true;
        
        try {
            if (fullUrl != null && !fullUrl.isEmpty()) {
                URL urlObj = new URL(fullUrl);
                basePath = urlObj.getPath();
                hostName = urlObj.getHost();
                port = urlObj.getPort();
                port = (port == -1) ? urlObj.getDefaultPort() : port;
                useHttps = "https".equalsIgnoreCase(urlObj.getProtocol());
                
                // 检查是否为文件URL
                Matcher matcher = TARGET_EXTENSION_PATTERN.matcher(basePath);
                isTargetFileUrl = matcher.find(); // 判断路径是否匹配目标扩展名

                if (isTargetFileUrl) {
                    // 定义poc (存储桶解析漏洞专用)
                    String newParam = "response-content-type=text/html";
                    // url.getQuery();判断url中是否存在？
                    String currentQuery = urlObj.getQuery();
                    if (currentQuery == null) {
                        // 无参数时拼接 ?param
                        modifiedUrl = basePath + "?" + newParam;
                    } else {
                        // 已有参数时拼接 &param
                        modifiedUrl = basePath + "&" + newParam;
                    }
                    
                    // 对于文件URL，提取目录路径用于其他测试
                    int lastSlashIndex = basePath.lastIndexOf('/');
                    if (lastSlashIndex > 0) {
                        // 提取目录路径
                        String directoryPath = basePath.substring(0, lastSlashIndex + 1);
                        paths.addAll(extractPaths(directoryPath));
                    } else {
                        paths.add("/");
                    }
                } else {
                    //将路径进行全量组合
                    if (!basePath.equals("/") && !basePath.isEmpty()){
                        paths.addAll(extractPaths(basePath));
                    }
                }
            }
        } catch (MalformedURLException e) {
            // URL解析失败，使用默认值
        }

        // 仅当 modifiedUrl 有效时添加
        if (modifiedUrl != null && !modifiedUrl.trim().isEmpty()) {
            currentPocList.add("GET " + modifiedUrl + " HTTP/1.1");
        }

        // 获取Map中所有的key
        for (Map.Entry<String, ArrayList<String>> entry : couldHashMap.entrySet()) {
            String cloudProvider = entry.getKey();
            ArrayList<String> hosts = entry.getValue();
            for (String host : hosts) {
                String hostIdentifier = host + ":" + cloudProvider; // 使用host和云服务商组合作为唯一标识
                if (!scannedHosts.contains(hostIdentifier)) { // 检查是否已经扫描过该主机名
                    scannedHosts.add(hostIdentifier); // 将主机名添加到已经扫描过的集合中
                    
                    // 如果hostName为空，从host中提取
                    if (hostName.isEmpty()) {
                        String[] hostParts = host.split(":");
                        hostName = hostParts[0];
                        port = hostParts.length > 1 ? Integer.parseInt(hostParts[1]) : 443;
                        useHttps = port == 443 || port == 8443;
                    }
                    
                    boolean bucketUploadFound = false; // 添加标志位，一旦发现可上传就停止后续PUT请求
                    
                    // 发送请求并分析响应
                    for (String poc : currentPocList) {
                        String[] parts = poc.split(" ", 3);
                        if (parts.length < 3) continue;
                        String method = parts[0];
                        String originalPath = parts[1];
                        String protocol = parts[2];
                        
                        // 如果是PUT请求，且已经发现可上传，则跳过
                        if (method.equals("PUT") && bucketUploadFound) {
                            continue;
                        }
                        
                        // 存储桶解析漏洞只针对文件URL进行测试，且只测试modifiedUrl
                        if (poc.equals("GET " + modifiedUrl + " HTTP/1.1")) {
                            // 只有文件URL才进行存储桶解析漏洞测试
                            if (isTargetFileUrl && modifiedUrl != null) {
                                String requestStr = method + " " + originalPath + " " + protocol;
                                String requestString = buildRequestString(requestStr, hostName);
                                String requestBody = "";
                                IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                                String message = null;
                                if (response != null && response.getResponse() != null) {
                                    boolean isHtmlResponse = checkHtmlResponse(helpers, response.getResponse(), modifiedUrl, "GET " + modifiedUrl + " HTTP/1.1");
                                    if (isHtmlResponse) {
                                        message = "存储桶解析漏洞";
                                    }
                                    if (message != null) {
                                        results.add(new RequestResponseWrapper(response, message, hostName));
                                    } else {
                                        results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                                    }
                                } else {
                                    results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                                }
                            }
                        } else {
                            // 其他漏洞测试，对所有路径进行测试
                            if (!paths.isEmpty()) {
                                for (String path : paths) {
                                    // 修复路径拼接问题：如果路径已经是目录格式，去除请求路径开头的斜杠
                                    String adjustedPath = path;
                                    if (path.endsWith("/") && originalPath.startsWith("/")) {
                                        originalPath = originalPath.substring(1);
                                    }
                                    String requestStr = method + " " + adjustedPath + originalPath + " " + protocol;
                                    String requestString = buildRequestString(requestStr, hostName);
                                    String requestBody = method.equals("PUT") ? "test content" : "";
                                    IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                                    String message = null;
                                    if (response != null && response.getResponse() != null) {
                                        message = analyzeResponse(helpers, response, cloudProvider, poc);
                                        // 如果发现上传漏洞，设置标志位
                                        if (message != null && message.equals("Bucket文件上传")) {
                                            bucketUploadFound = true;
                                        }
                                        if (message != null) {
                                            results.add(new RequestResponseWrapper(response, message, hostName));
                                        } else {
                                            results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                                        }
                                    } else {
                                        results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                                    }
                                }
                            } else {
                                // 没有额外路径的情况
                                String requestStr = method + " " + originalPath + " " + protocol;
                                String requestString = buildRequestString(requestStr, hostName);
                                String requestBody = method.equals("PUT") ? "test content" : "";
                                IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                                String message = null;
                                if (response != null && response.getResponse() != null) {
                                    message = analyzeResponse(helpers, response, cloudProvider, poc);
                                    // 如果发现上传漏洞，设置标志位
                                    if (message != null && message.equals("Bucket文件上传")) {
                                        bucketUploadFound = true;
                                    }
                                    if (message != null) {
                                        results.add(new RequestResponseWrapper(response, message, hostName));
                                    } else {
                                        results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                                    }
                                } else {
                                    results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                                }
                            }
                        }
                    }
                }
            }
        }

        return results;
    }

    /**
     * 主动扫描方法
     */
    public static List<RequestResponseWrapper> hostScan(
            IBurpExtenderCallbacks callbacks,
            IExtensionHelpers helpers,
            String host) {

        List<RequestResponseWrapper> results = new ArrayList<>();
        String modifiedUrl = null;
        String hostName = host;  // 原始URL
        int port = 443; // 默认HTTPS端口
        boolean useHttps = true; // 默认使用HTTPS
        List<String> paths = pathsHolder.get();
        paths.clear(); // 清空之前的数据
        
        // 构建POC列表
        List<String> currentPocList = new ArrayList<>(BASE_POC_LIST);
        String basePath = "/"; // 默认基础路径
        boolean isTargetFileUrl = false; // 标记是否为文件URL
        
        // 解析URL和构建modifiedUrl
        try {
            URL urlObj = new URL(host);
            basePath = urlObj.getPath();
            // 检查是否为文件URL
            Matcher matcher = TARGET_EXTENSION_PATTERN.matcher(basePath);
            isTargetFileUrl = matcher.find(); // 判断路径是否匹配目标扩展名

            if (isTargetFileUrl) {
                // 定义poc (存储桶解析漏洞专用)
                String newParam = "response-content-type=text/html";
                // url.getQuery();判断url中是否存在？
                String currentQuery = urlObj.getQuery();
                if (currentQuery == null) {
                    // 无参数时拼接 ?param
                    modifiedUrl = basePath + "?" + newParam;
                } else {
                    // 已有参数时拼接 &param
                    modifiedUrl = basePath + "&" + newParam;
                }
                
                // 对于文件URL，提取目录路径用于其他测试
                int lastSlashIndex = basePath.lastIndexOf('/');
                if (lastSlashIndex > 0) {
                    // 提取目录路径
                    String directoryPath = basePath.substring(0, lastSlashIndex + 1);
                    paths.addAll(extractPaths(directoryPath));
                } else {
                    paths.add("/");
                }
            } else {
                //将路径进行全量组合
                if (!basePath.equals("/") && !basePath.isEmpty()){
                    paths.addAll(extractPaths(basePath));
                }
            }

            hostName = urlObj.getHost(); // 提取纯主机名
            port = urlObj.getPort();
            port = (port == -1) ? urlObj.getDefaultPort() : port; // 如果端口为-1，使用默认端口
            useHttps = "https".equalsIgnoreCase(urlObj.getProtocol());
        } catch (MalformedURLException e) {
            // 处理非URL格式的输入
            int firstSlashIndex = host.indexOf('/');
            if (firstSlashIndex == -1) {
                firstSlashIndex = host.length(); // 没有路径
            }
            String hostAndPort = host.substring(0, firstSlashIndex);
            String[] parts = hostAndPort.split(":", 2);
            if (parts.length > 1) {
                try {
                    hostName = parts[0];
                    port = Integer.parseInt(parts[1]);
                    useHttps = port == 443; // 如果端口是443，我们认为它是HTTPS
                } catch (NumberFormatException ex) {
                    throw new RuntimeException("Invalid port format in host: " + host, ex);
                }
            } else {
                // 如果输入没有协议或端口，假设是HTTPS
                hostName = host;
            }
        }

        // 去掉可能存在的路径部分
        int pathIndex = hostName.indexOf("/");
        if (pathIndex != -1) {
            hostName = hostName.substring(0, pathIndex);
        }

        if (modifiedUrl != null && !modifiedUrl.trim().isEmpty()) {
            currentPocList.add("GET " + modifiedUrl + " HTTP/1.1");
        }

        boolean bucketUploadFound = false; // 添加标志位，一旦发现可上传就停止后续PUT请求


        String pocs = null;
        // 发送请求并分析响应
        for (String poc : currentPocList) {
            String[] parts = poc.split(" ", 3);
            if (parts.length < 3) continue;
            String method = parts[0];
            String originalPath = parts[1];
            String protocol = parts[2];
            
            // 如果是PUT请求，且已经发现可上传，则跳过
            if (method.equals("PUT") && bucketUploadFound) {
                continue;
            }
            
            if (modifiedUrl != null && poc.equals("GET " + modifiedUrl + " HTTP/1.1")) {
                String requestStr = method + " " + originalPath + " " + protocol;
                String requestString = buildRequestString(requestStr, hostName);
                String requestBody = "";
                IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                String message = null;
                if (response != null && response.getResponse() != null) {
                    boolean isHtmlResponse = checkHtmlResponse(helpers, response.getResponse(), modifiedUrl, "GET " + modifiedUrl + " HTTP/1.1");
                    if (isHtmlResponse) {
                        message = "存储桶解析漏洞";
                    }
                    if (message != null) {
                        results.add(new RequestResponseWrapper(response, message, hostName));
                    } else {
                        results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                    }
                } else {
                    results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                }
            } else {
                // 对于文件URL，只使用提取的目录路径
                List<String> pathsToTest = isTargetFileUrl ? paths : paths;
                
                if (!pathsToTest.isEmpty()) {
                    for (String path : pathsToTest) {
                        // 修复路径拼接问题：如果路径已经是目录格式，去除请求路径开头的斜杠
                        String adjustedPath = path;
                        if (path.endsWith("/") && originalPath.startsWith("/")) {
                            originalPath = originalPath.substring(1);
                        }
                        String requestStr = method + " " + adjustedPath + originalPath + " " + protocol;
                        
                        String requestString = buildRequestString(requestStr, hostName);
                        String requestBody = method.equals("PUT") ? "test content" : "";
                        IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                        String message = null;
                        if (response != null && response.getResponse() != null) {
                            message = analyzeResponse(helpers, response, null, poc);
                            // 如果发现上传漏洞，设置标志位
                            if (message != null && message.equals("Bucket文件上传")) {
                                bucketUploadFound = true;
                            }
                            if (message != null) {
                                results.add(new RequestResponseWrapper(response, message, hostName));
                                // 一旦发现可接管的Bucket，就跳出循环
                                if (message.equals("Bucket可接管")) {
                                    return results;
                                }
                            } else {
                                results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                            }
                        } else {
                            results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                        }
                    }
                } else {
                    // 没有额外路径的情况
                    String requestStr = method + " " + originalPath + " " + protocol;
                    String requestString = buildRequestString(requestStr, hostName);
                    String requestBody = method.equals("PUT") ? "test content" : "";
                    IHttpRequestResponse response = sendHttpRequest(helpers, callbacks, hostName, port, useHttps, requestString, requestBody);
                    String message = null;
                    if (response != null && response.getResponse() != null) {
                        message = analyzeResponse(helpers, response, null, poc);
                        // 如果发现上传漏洞，设置标志位
                        if (message != null && message.equals("Bucket文件上传")) {
                            bucketUploadFound = true;
                        }
                        if (message != null) {
                            results.add(new RequestResponseWrapper(response, message, hostName));
                        } else {
                            results.add(new RequestResponseWrapper(response, "未发现漏洞", hostName));
                        }
                    } else {
                        results.add(new RequestResponseWrapper(null, "Destination is unreachable", hostName));
                    }
                }
            }
        }
        return results;
    }

    /**
     * 构建HTTP请求字符串
     */
    private static String buildRequestString(String poc, String host) {
        StringBuilder requestBuilder = new StringBuilder(poc);
        requestBuilder.append(HOST_HEADER).append(host);
        requestBuilder.append(SEC_CH_UA_PLATFORM_HEADER);
        requestBuilder.append(USER_AGENT_HEADER);
        requestBuilder.append(CONNECTION_HEADER);
        return requestBuilder.toString();
    }

    /**
     * 发送HTTP请求
     */
    private static IHttpRequestResponse sendHttpRequest(
            IExtensionHelpers helpers,
            IBurpExtenderCallbacks callbacks,
            String hostName,
            int targetPort,
            boolean useHttps,
            String requestString,
            String requestBody) {

        try {
            byte[] requestBytes = requestString.getBytes(StandardCharsets.UTF_8);
            IRequestInfo analyzedRequest = helpers.analyzeRequest(requestBytes);
            List<String> headers = analyzedRequest.getHeaders();
            byte[] request = helpers.buildHttpMessage(headers, requestBody.getBytes(StandardCharsets.UTF_8));

            // 构建HTTP服务
            IHttpService httpService = helpers.buildHttpService(hostName, targetPort, useHttps);
            // 发送请求并获取响应
            return callbacks.makeHttpRequest(httpService, request);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * 检查是否为HTML响应（用于检测解析漏洞）
     */
    private static boolean checkHtmlResponse(
            IExtensionHelpers helpers,
            byte[] responseBytes,
            String modifiedUrl,
            String poc) {

        if (modifiedUrl == null) {
            return false;
        }

        // 只有特定的POC才检查
        if (poc.equals("GET " + modifiedUrl + " HTTP/1.1")) {
            IResponseInfo analyzeResponse = helpers.analyzeResponse(responseBytes);
            List<String> responseHeaders = analyzeResponse.getHeaders();

            for (String header : responseHeaders) {
                if (header.toLowerCase().contains("content-type: text/html")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * 分析响应并判断是否存在漏洞
     */
    private static String analyzeResponse(
            IExtensionHelpers helpers,
            IHttpRequestResponse response,
            String cloudProvider,
            String poc) {

        try {
            byte[] responseBytes = response.getResponse();
            String responseString = new String(responseBytes, StandardCharsets.UTF_8);
            IResponseInfo analyzeResponse = helpers.analyzeResponse(responseBytes);
            int statusCode = analyzeResponse.getStatusCode();

            if (statusCode == 200) {
                if (responseString.contains("</ListBucketResult>")) {
                    return "Bucket遍历";
                } else if (responseString.contains("<AccessControlPolicy>")) {
                    return "Bucket ACL可读";
                } else if (responseString.contains("\"Effect\": \"Allow\"")) { // 修复大小写问题
                    return "Bucket 权限策略为允许";
                } else if ((poc.startsWith("PUT ") && !responseString.contains("401") && !responseString.contains("403"))) { // 修复判断逻辑
                    // 华为云不支持文件上传检测
                    if (cloudProvider == null || !CLOUD_HUAWEI.equals(cloudProvider)) {
                        return "Bucket文件上传";
                    }
                }
            } else if (statusCode == 404 && poc.equals("GET / HTTP/1.1") && responseString.contains("The specified bucket does not exist")) {
                // 腾讯云例外处理
                if (cloudProvider == null || !CLOUD_TENCENT.equals(cloudProvider)) {
                    return "Bucket可接管";
                }
            }
        } catch (Exception e) {
            // 忽略异常
        }
        return null;
    }

    /**
     * 提取路径层级
     */
    public static List<String> extractPaths(String uri) {
        // 动态生成不同层级的路径并存储到列表中
        List<String> paths = new ArrayList<>();
        StringBuilder basePathBuilder = new StringBuilder();

        if (uri == null){
            return paths;
        }
        // 去除末尾斜杠
        if (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        // 拆分路径段
        String[] segments = uri.split("/");
        // 遍历路径段，构建路径
        for (int i = 1; i < segments.length; i++) { // 从1开始，跳过第一个空字符串
            String segment = segments[i];
            if (!segment.isEmpty()) {
                basePathBuilder.append('/').append(segment);
                paths.add(basePathBuilder.toString() + "/");
            }
        }
        //添加根路径
        paths.add("/");
        // 反转列表，从详细到基础
        Collections.reverse(paths);

        return paths;
    }

    /**
     * 请求响应包装类
     */
    public static class RequestResponseWrapper {
        private final IHttpRequestResponse requestResponse;
        private final String message;
        private final String hosts;

        public RequestResponseWrapper(IHttpRequestResponse requestResponse, String message, String hosts) {
            this.requestResponse = requestResponse;
            this.message = message;
            this.hosts = hosts;
        }

        public IHttpRequestResponse getRequestResponse() {
            return requestResponse;
        }

        public String getMessage() {
            return message;
        }

        public String getHosts(){
            return hosts;
        }
    }
}