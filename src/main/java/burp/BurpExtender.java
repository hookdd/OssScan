package burp;

import burp.Utils.Date_tidy;
import burp.Utils.Poc_Scan;
import burp.ui.InitiativeScan;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import java.awt.Toolkit;
import static burp.Utils.Date_tidy.mergeMaps;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IMessageEditorController {

    private IExtensionHelpers helpers;
    private static IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;

    private JScrollPane urlJScrollPane;

    private JTabbedPane Ltable;
    private JTabbedPane Rtable;

    private JTabbedPane M_JTabbedPane;
    private JSplitPane TopAndDown_SplitPane;
    private JSplitPane RqAndRp_SplitPane;

    private ArrayList<TablesData> Udatas = new ArrayList();

    //定义一个获取到oos地址列表
    private HashMap<String, ArrayList<String>> CouldHashMap = new HashMap<>();

    private URLTable Utable;
    // 新增 IProxyListener 成员变量
    private IProxyListener proxyListener;
    //响应包过滤
    public static final Set<String> unLegalExtensionSet = new HashSet<>(Arrays.asList(
            // 视频格式（无文本内容）
            "mp4", "avi", "mov", "wmv", "flv", "mpeg", "mpg", "mpe", "ogv", "webm", "3gp", "3g2",
            // 音频格式
            "mp3", "wav", "aac", "midi", "mid", "oga", "ra", "aiff", "au", "weba", "snd",
            // 压缩文件
            "zip", "rar", "7z", "gz", "bz2", "bz", "tar", "cab", "arc",
            // 其他二进制
            "exe", "dll", "so", "class", "jar", "swf", "rmvb", "rm", "bin", "dat", "cab"
    ));
    // BurpExtender.java (注册代理监听器时)
    private final ExecutorService scanExecutor = Executors.newFixedThreadPool(3);

    //预编译正则
    private static final String[] targetExtensions = {".txt",".js", ".json", ".png",".jpg",".pdf",".zip"};
    private static final String regex = ".*(" + String.join("|", targetExtensions) + ")$";

    private static String modifiedUrl =null;

    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        this.callbacks = iBurpExtenderCallbacks;
        // 获取 helpers ,该方法不能在this.callbacks = iBurpExtenderCallbacks;之前
        this.helpers = callbacks.getHelpers();
        // 设置插件名字
        this.callbacks.setExtensionName("OSS_Scan");
        // 打印信息在UI控制台页面
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println("安装成功");
        stdout.println("对于acl、policy策略只有读取扫描，是否可以上传需要自行尝试。");
        stdout.println("OSS_Scan_1.6");
        // 初始化 UI 界面
        M_JTabbedPane = new JTabbedPane();
        //分割线
        TopAndDown_SplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        //url 表格
        Utable = new URLTable(new URLTableModel(Udatas));
        urlJScrollPane = new JScrollPane(Utable);
        //添加到主页面
        TopAndDown_SplitPane.setTopComponent(urlJScrollPane);
        // 初始化请求和响应编辑器
        HRequestTextEditor = callbacks.createMessageEditor(BurpExtender.this, false);
        HResponseTextEditor = callbacks.createMessageEditor(BurpExtender.this, false);
        // 构建请求、响应分割线
        RqAndRp_SplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        //请求和响应各自占领的比例，一人一半
        RqAndRp_SplitPane.setResizeWeight(0.5);
        // 初始化请求/响应ui
        Ltable = new JTabbedPane();
        Rtable = new JTabbedPane();
        // 构建请求/响应 UI
        Ltable.addTab("Request", HRequestTextEditor.getComponent());
        Rtable.addTab("Response", HResponseTextEditor.getComponent());
        RqAndRp_SplitPane.setLeftComponent(Ltable);
        RqAndRp_SplitPane.setRightComponent(Rtable);
        //添加请求响应到主面板
        TopAndDown_SplitPane.setBottomComponent(RqAndRp_SplitPane);

        //添加请求响应到主页面
        M_JTabbedPane.add("passive Scan", TopAndDown_SplitPane);
        //第二ui界面编写
        InitiativeScan initiativeScan = new InitiativeScan();
        JSplitPane jSplitPane = initiativeScan.InitiativeUI();
        M_JTabbedPane.add("initiative Scan", jSplitPane);

        // 注册 Tab
        this.callbacks.addSuiteTab(this);
        // 注册代理监听器
        proxyListener = new IProxyListener() {
            @Override
            public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
                // 获取请求信息
                IHttpRequestResponse messageInfo = message.getMessageInfo();
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);
                //获取oss地址的来源
                String source_url = String.valueOf(analyzeRequest.getUrl());

                IHttpService httpService = messageInfo.getHttpService();
                String hostName = httpService.getHost();
                URL url = analyzeRequest.getUrl();
                String path = url.getPath(); // 示例：/files/xxx/1704866466827png
                int lastDotIndex = path.lastIndexOf('.');
                String type = "";
                if (lastDotIndex != -1 && lastDotIndex < path.length() - 1) {
                    type = path.substring(lastDotIndex + 1).toLowerCase();
                }
                // 定义需要处理的扩展名列表
                Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(path);
                boolean isTargetFile = matcher.find(); // 判断路径是否匹配目标扩展名

                String newParam = "response-content-type=text/html";
                //url.getQuery();判断url中是否存在？
                String currentQuery = url.getQuery();
                if (isTargetFile) {
                    if (currentQuery == null) {
                        // 无参数时拼接 ?param
                        modifiedUrl = path + "?" + newParam;
                    } else {
                        // 已有参数时拼接 &param
                        modifiedUrl = path + "&" + newParam;
                    }
                }
                //messageIsRequest为ture时候为请求信息，为false时候为响应信息
                if (messageIsRequest) {
                    //通过host特征判断是否为云oss
                    HashMap<String, ArrayList<String>> requestData = Date_tidy.extractCloudHosts(hostName);
                    mergeMaps(CouldHashMap,requestData); // 合并请求数据
                }else{
                    // 处理响应
                    byte[] response = messageInfo.getResponse();
                    String responseString = null;
                    try {
                        //获取所有响应头
                        IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
                        List<String> headers = analyzeResponse.getHeaders();
                        //ExtractHeaders判读是否为存储桶
                        HashMap<String, ArrayList<String>> headersData = Date_tidy.ExtractHeaders(headers,hostName);
                        mergeMaps(CouldHashMap, headersData);
                        //对黑名单格式的响应不进行正则匹配
                        if (response != null && !unLegalExtensionSet.contains(type)){
                            responseString = new String(response, "UTF-8");
                            HashMap<String, ArrayList<String>> responseData = Date_tidy.extractCloudHosts(responseString);
                            mergeMaps(CouldHashMap, responseData); // 合并响应数据
                        }
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                    }
                }

                if (!CouldHashMap.isEmpty()){
                    scanExecutor.submit(() -> {
                        List<Poc_Scan.RequestResponseWrapper> requestResponseWrappers = Poc_Scan.buildHttpServiceFromUrl(callbacks, helpers, CouldHashMap, messageInfo,modifiedUrl);
                        SwingUtilities.invokeLater(() -> {
                            // 更新UI
                            for (Poc_Scan.RequestResponseWrapper requestResponseWrapper : requestResponseWrappers) {
                                IHttpRequestResponse requestResponse = requestResponseWrapper.getRequestResponse();
                                String message1 = requestResponseWrapper.getMessage();
                                String hosts = requestResponseWrapper.getHosts();
                                //因为如果是华为云的话会返回空的requestResponse、message1等，但是id还是会自增，为了防止所以if判断
                                if (message1 != null && !message1.isEmpty()) {
                                    Udatas.add(new TablesData(Udatas.size() + 1, source_url, hosts, message1, requestResponse));
                                    ((URLTableModel) Utable.getModel()).fireTableDataChanged(); // 通知表格数据已更改，将获取的数据在表格显示
                                }
                            }
                        });
                    });
                }

            }
        };
        callbacks.registerProxyListener(proxyListener);
    }

    @Override
    public int getRowCount() {
        return 0;
    }

    @Override
    public int getColumnCount() {
        return 0;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        return null;
    }


    // 定义了一个继承自 AbstractTableModel 的 URLTableModel 类
    class URLTableModel extends AbstractTableModel {
        // 定义了一个字符串数组，用于存储表格的列名
        private final String[] columnNames = {"ID","SourceURL", "OSS", "Issue"};

        // 定义了一个 ArrayList，用于存储表格数据，类型为 BurpExtender.TablesData
        private final ArrayList<BurpExtender.TablesData> Udatas;

        // 构造函数，接收一个包含表格数据的 ArrayList
        public URLTableModel(ArrayList<BurpExtender.TablesData> Udatas) {
            this.Udatas = Udatas;
        }

        // 实现 getRowCount 方法，返回表格的行数，即数据列表的大小
        @Override
        public int getRowCount() {
            return Udatas.size();
        }

        // 实现 getColumnCount 方法，返回表格的列数，即列名数组的长度
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        // 实现 getColumnName 方法，根据给定的列索引返回相应的列名
        @Override
        public String getColumnName(int columnIndex) {
            return columnNames[columnIndex];
        }

        // 实现 getValueAt 方法，根据给定的行和列索引返回单元格的值
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            // 获取指定行的数据对象
            TablesData datas = Udatas.get(rowIndex);
            // 根据列索引返回相应的值
            switch (columnIndex) {
                case 0: // ID 列
                    return datas.Id;
                case 1: // URL 列
                    return datas.Source;
                case 2: // URL 列
                    return datas.URL;
                case 3: // Issue 列
                    return datas.issue;
                default:
                    return null; // 如果列索引无效，则返回 null
            }
        }
        // 清除表格数据的方法
        public void clearData() {
            Udatas.clear();
            fireTableDataChanged();
        }

        // 删除特定行的方法
        public void removeRow(int row) {
            if (row >= 0 && row < Udatas.size()) {
                Udatas.remove(row);
                fireTableRowsDeleted(row, row); // 通知表格已删除一行
            }
        }
        //复制所有行的url请请求
        public void copyUrl(int row) {
            if (row >= 0 && row < Udatas.size()) {
                TablesData dataEntry = Udatas.get(row);
                if (dataEntry != null && dataEntry.requestResponse != null) {
                    try {
                        // 获取HTTP服务信息（Host和端口）
                        IHttpService httpService = dataEntry.requestResponse.getHttpService();

                        // 解析请求URL路径
                        byte[] request = dataEntry.requestResponse.getRequest();
                        String requestString = new String(request, "UTF-8");
                        String[] lines = requestString.split("\r\n");
                        String[] s1 = lines[0].split(" ");
                        String path = s1[1];
                        // 构造完整URL（格式：https://host/path）
                        String fullUrl = "https://" + httpService.getHost() + path;

                        // 复制到剪贴板
                        StringSelection selection = new StringSelection(fullUrl);
                        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                        clipboard.setContents(selection, null);
                    } catch (Exception e) {
                        stdout.println("Error copying URL: " + e.getMessage());
                    }
                }
            }
        }
    }
    @Override
    public IHttpService getHttpService() {
        return null;
    }

    @Override
    public byte[] getRequest() {
        return new byte[0];
    }

    @Override
    public byte[] getResponse() {
        return new byte[0];
    }

    //存储每行数据
    public static class TablesData {
        final int Id;
        final String Source;
        final String URL;
        final String issue;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id, String Source,String url, String vul, IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.Source = Source;
            this.URL = url;
            this.issue = vul;
            this.requestResponse = requestResponse;
        }
    }
    //用于显示TablesData列表中的数据，并处理表格选择事件
    public class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            setupPopupMenu(); // 在构造函数中调用
        }
        private void setupPopupMenu() {
            JPopupMenu popupMenu = new JPopupMenu();

            JMenuItem clearAll = new JMenuItem("Clear All");
            clearAll.addActionListener(e -> {
                ((URLTableModel) getModel()).clearData();
            });

            JMenuItem deleteRow = new JMenuItem("Delete Selected Row");
            deleteRow.addActionListener(e -> {
                int selectedRow = getSelectedRow();
                if (selectedRow != -1) {
                    ((URLTableModel) getModel()).removeRow(selectedRow);
                }
            });
            //复制请求url
            JMenuItem CopyUrl = new JMenuItem("copy url");
            CopyUrl.addActionListener(e -> {
                int selectedRow = getSelectedRow();
                if (selectedRow != -1){
                    ((URLTableModel) getModel()).copyUrl(selectedRow);
                }
            });

            popupMenu.add(clearAll);
            popupMenu.add(deleteRow);
            popupMenu.add(CopyUrl);
            this.setComponentPopupMenu(popupMenu);
        }

        //选中表格中的某一行
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            super.changeSelection(row, col, toggle, extend);
            // 从模型中获取当前行的数据
            BurpExtender.URLTableModel model = (BurpExtender.URLTableModel) getModel();
            BurpExtender.TablesData dataEntry = model.Udatas.get(convertRowIndexToModel(row));

            if (dataEntry != null && dataEntry.requestResponse != null) {
                HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
                currentlyDisplayedItem = dataEntry.requestResponse;
            }
        }
    }
    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return callbacks.getHelpers();
    }


    // 返回 Tab 的名字
    public String getTabCaption() {
        return "oss_Scan";
    }

    // 返回 UI 的主界面变量
    public Component getUiComponent() {
        return M_JTabbedPane;
    }
}