package burp.Utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Date_tidy {

    //根据不同云之间的漏洞定义不同的漏洞标识
    public static final String Cloud_Alibaba ="Cloud_Alibaba";
    public static final String Cloud_TengXun = "Cloud_TengXun";
    public static final String Cloud_HuaWei = "Cloud_HuaWei";
    public static final String Cloud_AWS = "Cloud_AWS";
    public static final String Cloud_CTYUN = "Cloud_CTYUN";
    public static final String Cloud_JDCloud = "Cloud_JDCloud";
    public static final String Cloud_Qnm = "Cloud_Qnm";

    //合并数据
    /**
     * 合并两个Map，将source中的条目添加到target
     * @param target 目标Map（被合并的对象）
     * @param source 来源Map（提供新数据）
     */
    public static void mergeMaps(Map<String, ArrayList> target,  Map<String, ArrayList> source) {
        source.forEach((key, newHosts) -> {
            // 获取或创建目标列表（自动类型推断，无需转换）
            List<String> existingHosts = target.getOrDefault(key, new ArrayList<>());
            // 使用HashSet加速去重（O(1)查找）
            Set<String> existingSet = new HashSet<>(existingHosts);
            // 过滤新Hosts中不重复的元素
            List<String> uniqueHosts = (List<String>) newHosts.stream()
                    .filter(host -> !existingSet.contains(host))
                    .collect(Collectors.toList());
            // 直接修改existingHosts（已关联target）
            if (!uniqueHosts.isEmpty()) {
                existingHosts.addAll(uniqueHosts);
            }
        });
//        Set<String> allHosts = new HashSet<>();
//        // 收集 target 中已有的所有 host
//        for (ArrayList<String> hosts : target.values()) {
//            allHosts.addAll(hosts);
//        }
//
//        // 合并 source，过滤已存在的 host
//        for (Map.Entry<String, ArrayList> entry: source.entrySet()) {
//            String key = entry.getKey();
//            ArrayList<String> values = entry.getValue();
//            ArrayList<String> filteredValues = new ArrayList<>();
//
//            for (String host : values) {
//                if (!allHosts.contains(host)) {
//                    filteredValues.add(host);
//                    allHosts.add(host); // 记录已合并的 host
//                }
//            }
//
//            if (!filteredValues.isEmpty()) {
//                if (target.containsKey(key)) {
//                    target.get(key).addAll(filteredValues);
//                } else {
//                    target.put(key, new ArrayList<>(filteredValues));
//                }
//            }
//        }
    }
    public static HashMap<String, ArrayList> ExtractHeaders(List<String> headers,String host) {
        HashMap<String, ArrayList> Cnamehost = new HashMap<>();
        for (String header : headers) {
            String headerLower = header.toLowerCase(); // 统一转为小写
            if (headerLower.contains("x-obs")){
                Cnamehost.computeIfAbsent(Cloud_HuaWei, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-cos")) {
                Cnamehost.computeIfAbsent(Cloud_TengXun, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-oss")) {
                Cnamehost.computeIfAbsent(Cloud_Alibaba, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-amz")) {
                Cnamehost.computeIfAbsent(Cloud_AWS, k -> new ArrayList<>()).add(host);
            } else if (headerLower.contains("x-qiniu") || headerLower.contains("x-qnm")) {
                Cnamehost.computeIfAbsent(Cloud_Qnm, k -> new ArrayList<>()).add(host);
            }
        }
        return Cnamehost;
    }


    // 提取 OSSURL 地址
    public static String extractUrl(byte[] request) {
        try {
            // 解析请求头
            String requestString = new String(request, "UTF-8");
            String[] lines = requestString.split("\\r?\\n");
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

    private static final Pattern HUAWEI_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.obs\\.[a-zA-Z0-9-.]+\\.myhuaweicloud\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TENCENT_PATTERN = Pattern.compile("([a-zA-Z0-9-]+-[0-9]+\\.cos\\.[a-zA-Z0-9-.]+\\.myqcloud\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ALIBABA_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+\\.aliyuncs\\.com)", Pattern.CASE_INSENSITIVE);
    private static final Pattern AWS_PATTERN = Pattern.compile("([a-zA-Z0-9.-]+\\.(?:s3(?:-website)?\\.?[a-zA-Z0-9.-]*\\.amazonaws\\.com))",Pattern.CASE_INSENSITIVE);
    private static final Pattern CTYUN_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.zos\\.ctyun\\.cn)",Pattern.CASE_INSENSITIVE);
    private static final Pattern JDCLOUD_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9-]+\\.jcloud\\.com)",Pattern.CASE_INSENSITIVE);
    private static final Pattern QNM_PATTERN = Pattern.compile("([a-zA-Z0-9-]+\\.[a-zA-Z0-9.-]+\\.qnssl\\.com)",Pattern.CASE_INSENSITIVE);


    public static HashMap<String, ArrayList> extractCloudHosts(String text) {
        HashMap<String, ArrayList> CouldHashMap = new HashMap<>();

        // 匹配并提取华为云 OBS
        Matcher huaweiObsMatcher = HUAWEI_PATTERN.matcher(text);
        while (huaweiObsMatcher.find()) {
            ArrayList<String> huaweiHosts = new ArrayList<>();
            huaweiHosts.add(huaweiObsMatcher.group(1));
            CouldHashMap.put(Cloud_HuaWei,huaweiHosts);
        }

        // 匹配并提取腾讯云 COS
        Matcher tencentCosMatcher = TENCENT_PATTERN.matcher(text);
        while (tencentCosMatcher.find()) {
            ArrayList<String> tencentHosts = new ArrayList<>();
            tencentHosts.add(tencentCosMatcher.group(1));
            CouldHashMap.put(Cloud_TengXun,tencentHosts);
        }

        // 匹配并提取阿里云 OSS
        Matcher aliYunOssMatcher = ALIBABA_PATTERN.matcher(text);
        while (aliYunOssMatcher.find()) {
            ArrayList<String> aliYunHosts = new ArrayList<>();
            aliYunHosts.add(aliYunOssMatcher.group(1));
            CouldHashMap.put(Cloud_Alibaba,aliYunHosts);
        }


        // 匹配并提取 AWS S3
        Matcher awsS3Matcher4 = AWS_PATTERN.matcher(text);
        while (awsS3Matcher4.find()) {
            ArrayList<String> awsHosts = new ArrayList<>();
            awsHosts.add(awsS3Matcher4.group(1));
            CouldHashMap.put(Cloud_AWS,awsHosts);
        }

        // 匹配并提取天翼云
        Matcher ctyunMatcher = CTYUN_PATTERN.matcher(text);
        while (ctyunMatcher.find()) {
            ArrayList<String> ctyunHosts = new ArrayList<>();
            ctyunHosts.add(ctyunMatcher.group(1));
            CouldHashMap.put(Cloud_CTYUN, ctyunHosts);
        }
        // 匹配并提取京东云
        Matcher jdCloudMatcher = JDCLOUD_PATTERN.matcher(text);
        while (jdCloudMatcher.find()) {
            ArrayList<String> jdCloudHosts = new ArrayList<>();
            jdCloudHosts.add(jdCloudMatcher.group(1));
            CouldHashMap.put(Cloud_JDCloud, jdCloudHosts);
        }
        // 匹配并提取七牛云
        Matcher qiniuMatcher = QNM_PATTERN.matcher(text);
        while (qiniuMatcher.find()) {
            ArrayList<String> qiniuHosts = new ArrayList<>();
            qiniuHosts.add(qiniuMatcher.group(1));
            CouldHashMap.put(Cloud_Qnm, qiniuHosts);
        }
        return CouldHashMap;
    }
}
