package burp.Utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Date_tidy {

    //根据不同云之间的漏洞定义不同的漏洞标识
    public static final String Cloud_Alibaba ="Cloud_Alibaba";
    public static final String Cloud_TengXun = "Cloud_TengXun";
    public static final String Cloud_HuaWei = "Cloud_HuaWei";
    public static final String Cloud_AWS = "Cloud_AWS";
    public static final String Cloud_CTYUN = "Cloud_CTYUN";

    public static final String Cloud_JDCloud = "Cloud_JDCloud";

    // 提取 OSSURL 地址
    public static String extractUrl(byte[] request) {
        try {
            // 解析请求头
            String requestString = new String(request, "UTF-8");
            String[] lines = requestString.split("\r\n");
            for (String line : lines) {
                if (line.toLowerCase().startsWith("host:")) {
                    String host=line.substring(5).trim();
                    return host;
                }
            }
            return "Unknown Host";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error extracting Host";
        }
    }
    public static String extractRequestUrl(IHttpRequestResponse messageInfo, boolean includePath) {
        if (messageInfo == null) {
            return null;
        }

        byte[] request = messageInfo.getRequest();
        if (request == null || request.length == 0) {
            return null;
        }
        IExtensionHelpers helpers = BurpExtender.getHelpers();
        IRequestInfo requestInfo = helpers.analyzeRequest(request);
        String requestLine = new String(request, 0, requestInfo.getBodyOffset()).trim();
        String[] parts = requestLine.split(" ");

        // 获取请求的方法和路径
        String path = parts[1];

        // 获取Host头
        String hostHeader = extractUrl(request); // 使用已有的方法

        if ("Unknown Host".equals(hostHeader) || "Error extracting Host".equals(hostHeader)) {
            return null; // 如果没有找到Host头，返回null
        }

        // 直接获取协议
        boolean useHttps = messageInfo.getHttpService().getProtocol().equalsIgnoreCase("https");
        String protocol = useHttps ? "https" : "http";

        // 组合URL
//        String url = protocol + "://" + hostHeader + path;
        // 组合URL
        String url = protocol + "://" + hostHeader;
        if (includePath) {
            url += path;
        }
        return url;
    }

    public static HashMap<String, ArrayList> extractCloudHosts(String text) {
        HashMap<String, ArrayList> CouldHashMap = new HashMap<>();

        // 定义各种云服务提供商的正则表达式
        String huaweiObsRegex = "([a-zA-Z0-9-]+\\.obs\\.[a-zA-Z0-9-.]+\\.myhuaweicloud\\.com)";
        String tencentCosRegex = "([a-zA-Z0-9-]+-[0-9]+\\.cos\\.[a-zA-Z0-9-.]+\\.myqcloud\\.com)";
        String aliYunOssRegex = "([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+\\.aliyuncs\\.com)";
        String awsS3Regex4 ="(?:https?://)?([a-zA-Z0-9.-]+\\.(?:s3(?:-website)?\\.?[a-zA-Z0-9.-]*\\.amazonaws\\.com))";
        String ctyunRegex = "([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.zos\\.ctyun\\.cn)";
        String jdCloudRegex = "https?://([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.jcloud\\.com)";

        // 编译正则表达式
        Pattern huaweiObsPattern = Pattern.compile(huaweiObsRegex, Pattern.CASE_INSENSITIVE);
        Pattern tencentCosPattern = Pattern.compile(tencentCosRegex, Pattern.CASE_INSENSITIVE);
        Pattern aliYunOssPattern = Pattern.compile(aliYunOssRegex, Pattern.CASE_INSENSITIVE);
        Pattern awsS3Pattern4 = Pattern.compile(awsS3Regex4, Pattern.CASE_INSENSITIVE);
        Pattern ctyunPattern = Pattern.compile(ctyunRegex, Pattern.CASE_INSENSITIVE);
        Pattern jdCloudPattern = Pattern.compile(jdCloudRegex, Pattern.CASE_INSENSITIVE);

        // 匹配并提取华为云 OBS
        Matcher huaweiObsMatcher = huaweiObsPattern.matcher(text);
        while (huaweiObsMatcher.find()) {
            ArrayList<String> huaweiHosts = new ArrayList<>();
            huaweiHosts.add(huaweiObsMatcher.group(1));
            CouldHashMap.put(Cloud_HuaWei,huaweiHosts);
        }

        // 匹配并提取腾讯云 COS
        Matcher tencentCosMatcher = tencentCosPattern.matcher(text);
        while (tencentCosMatcher.find()) {
            ArrayList<String> tencentHosts = new ArrayList<>();
            tencentHosts.add(tencentCosMatcher.group(1));
            CouldHashMap.put(Cloud_TengXun,tencentHosts);
        }

        // 匹配并提取阿里云 OSS
        Matcher aliYunOssMatcher = aliYunOssPattern.matcher(text);
        while (aliYunOssMatcher.find()) {
            ArrayList<String> aliYunHosts = new ArrayList<>();
            aliYunHosts.add(aliYunOssMatcher.group(1));
            CouldHashMap.put(Cloud_Alibaba,aliYunHosts);
        }


        // 匹配并提取 AWS S3
        Matcher awsS3Matcher4 = awsS3Pattern4.matcher(text);
        while (awsS3Matcher4.find()) {
            ArrayList<String> awsHosts = new ArrayList<>();
            awsHosts.add(awsS3Matcher4.group(1));
            CouldHashMap.put(Cloud_AWS,awsHosts);
        }

        // 匹配并提取天翼云
        Matcher ctyunMatcher = ctyunPattern.matcher(text);
        while (ctyunMatcher.find()) {
            ArrayList<String> ctyunHosts = new ArrayList<>();
            ctyunHosts.add(ctyunMatcher.group(1));
            CouldHashMap.put(Cloud_CTYUN, ctyunHosts);
        }
        // 匹配并提取京东云
        Matcher jdCloudMatcher = jdCloudPattern.matcher(text);
        while (ctyunMatcher.find()) {
            ArrayList<String> jdCloudHosts = new ArrayList<>();
            jdCloudHosts.add(jdCloudMatcher.group(1));
            CouldHashMap.put(Cloud_JDCloud, jdCloudHosts);
        }
        return CouldHashMap;
    }
}
