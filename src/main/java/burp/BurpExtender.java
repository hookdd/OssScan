package burp;

import burp.Utils.Date_tidy;
import burp.Utils.Poc_Scan;
import burp.ui.InitiativeScan;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.*;

import static burp.Utils.Date_tidy.extractRequestUrl;

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
    private HashMap<String, ArrayList> CouldHashMap = new HashMap<>();

    private URLTable Utable;
    // 新增 IProxyListener 成员变量
    private IProxyListener proxyListener;




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
                String source_url = extractRequestUrl(messageInfo);
                //messageIsRequest为ture时候为请求信息，为false时候为响应信息
                if (messageIsRequest) {
                    byte[] request = messageInfo.getRequest();
                    //获取到所有请求的host
                    String requesthost  = Date_tidy.extractUrl(request);
                    //正则匹配查看是否否和oss的类型
                    CouldHashMap = Date_tidy.extractCloudHosts(requesthost);
                }else{
                    // 处理响应
                    byte[] response = messageInfo.getResponse();
                    String responseString = null;
                    try {
                        responseString = new String(response, "UTF-8");
                        CouldHashMap = Date_tidy.extractCloudHosts(responseString);
                    } catch (UnsupportedEncodingException e) {
                        throw new RuntimeException(e);
                    }
                }
                //使用 lastRequestHost 来代替 requesthost
                if (!CouldHashMap.isEmpty()){
                    Poc_Scan.RequestResponseWrapper responseWrapper = Poc_Scan.buildHttpServiceFromUrl(callbacks, helpers, CouldHashMap);
                    IHttpRequestResponse requestResponse = responseWrapper.getRequestResponse();
                    String message1 = responseWrapper.getMessage();
                    String hosts = responseWrapper.getHosts();
                    //因为如果是华为云的话会返回空的requestResponse、message1等，但是id还是会自增，为了防止所以if判断
                    if (message1 != null && !message1.isEmpty()) {
                        Udatas.add(new TablesData(Udatas.size() + 1, source_url, hosts, message1, requestResponse));
                        ((URLTableModel) Utable.getModel()).fireTableDataChanged(); // 通知表格数据已更改，将获取的数据在表格显示
                    }
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

            popupMenu.add(clearAll);
            popupMenu.add(deleteRow);
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