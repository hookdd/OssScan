package burp.ui;

import burp.*;
import burp.Utils.Poc_Scan;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import static burp.Utils.Poc_Scan.hostScan;

public  class InitiativeScan extends AbstractTableModel implements ITab, IMessageEditorController {
    IExtensionHelpers helpers = BurpExtender.getHelpers();

    IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();
    ArrayList<InitiativeScan.TablesData> Udatas = new ArrayList();
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private InitiativeScan.URLTable Utable;


    public JSplitPane InitiativeUI() {
        JSplitPane TopAndDown_SplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 创建顶部面板
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new FlowLayout(FlowLayout.CENTER));  // 居中布局

        // 创建文本框
        final JTextField textField = new JTextField(30);
        topPanel.add(textField);

        // 创建按钮
        JButton addBtn = new JButton("Scan");
        addBtn.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String host = textField.getText();
                if (host == null || host.trim().isEmpty()) {
                    JOptionPane.showMessageDialog(TopAndDown_SplitPane, "输入不能为空！", "警告", JOptionPane.WARNING_MESSAGE);
                } else {
                    // 使用SwingWorker来异步执行HTTP请求
                    new SwingWorker<List<Poc_Scan.RequestResponseWrapper>, Void>() {
                        @Override
                        protected List<Poc_Scan.RequestResponseWrapper> doInBackground() throws Exception {
                            List<Poc_Scan.RequestResponseWrapper> requestResponseWrappers = hostScan(callbacks, helpers, host);
                            if (requestResponseWrappers == null || requestResponseWrappers.isEmpty()) {
                                throw new Exception("未获取到扫描结果");
                            }
                            return requestResponseWrappers; // 返回整个列表
                        }
                        @Override
                        protected void done() {
                            try {
                                List<Poc_Scan.RequestResponseWrapper> responseWrapper = get();
                                if (responseWrapper != null) {
                                    for (Poc_Scan.RequestResponseWrapper wrapper : responseWrapper) {
                                        IHttpRequestResponse requestResponse = wrapper.getRequestResponse();
                                        String message1 = wrapper.getMessage();
                                        String hosts = wrapper.getHosts();
                                        if (message1 != null && !message1.isEmpty()) {
                                            SwingUtilities.invokeLater(() -> {
                                                Udatas.add(new TablesData(Udatas.size() + 1, hosts, message1, requestResponse));
                                                ((URLTableModel) Utable.getModel()).fireTableDataChanged(); // 通知表格数据已更改
                                            });
                                        }
                                    }
                                }
                            } catch (Exception ex) {
                                // 在这里处理异常
                                SwingUtilities.invokeLater(() -> {
                                    JOptionPane.showMessageDialog(TopAndDown_SplitPane, "扫描过程中发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                                });
                            }
                        }
                    }.execute();
                }
            }
        });
        topPanel.add(addBtn);

        //url 表格
        Utable = new URLTable(new URLTableModel(Udatas));
        JScrollPane urlJScrollPane = new JScrollPane(Utable);
        // 初始化请求和响应编辑器
        HRequestTextEditor = callbacks.createMessageEditor(InitiativeScan.this, false);
        HResponseTextEditor = callbacks.createMessageEditor(InitiativeScan.this, false);
        // 构建请求、响应分割线
        JSplitPane RqAndRp_SplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        //请求和响应各自占领的比例，一人一半
        RqAndRp_SplitPane.setResizeWeight(0.5);
        // 初始化请求/响应ui
        JTabbedPane Ltable = new JTabbedPane();
        JTabbedPane Rtable = new JTabbedPane();
        // 构建请求/响应 UI
        Ltable.addTab("Request", HRequestTextEditor.getComponent());
        Rtable.addTab("Response", HResponseTextEditor.getComponent());
        RqAndRp_SplitPane.setLeftComponent(Ltable);
        RqAndRp_SplitPane.setRightComponent(Rtable);

        // 创建一个新的水平分割的 JSplitPane 来容纳 urlJScrollPane 和 RqAndRp_SplitPane
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        bottomSplitPane.setLeftComponent(urlJScrollPane);
        bottomSplitPane.setRightComponent(RqAndRp_SplitPane);
        bottomSplitPane.setResizeWeight(0.5);  // 设置初始分割比例
        // 设置顶部面板
        TopAndDown_SplitPane.setTopComponent(topPanel);
        // 设置底部面板为新的水平分割面板
        TopAndDown_SplitPane.setBottomComponent(bottomSplitPane);
        return TopAndDown_SplitPane;
    }
    class URLTableModel extends AbstractTableModel {
        // 定义了一个字符串数组，用于存储表格的列名
        private final String[] columnNames = {"ID","OSS","Issue"};

        // 定义了一个 ArrayList，用于存储表格数据，类型为 BurpExtender.TablesData
        private final ArrayList<InitiativeScan.TablesData> Udatas;

        // 构造函数，接收一个包含表格数据的 ArrayList
        public URLTableModel(ArrayList<InitiativeScan.TablesData> Udatas) {
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
                    return datas.URL;
                case 2: // Issue 列
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
    public static class TablesData {
        final int Id;
        final String URL;
        final String issue;
        final IHttpRequestResponse requestResponse;

        public TablesData(int id,String url, String vul, IHttpRequestResponse requestResponse) {
            this.Id = id;
            this.URL = url;
            this.issue = vul;
            this.requestResponse = requestResponse;
        }
    }
    //用于显示TablesData列表中的数据，并处理表格选择事件
    public  class URLTable extends JTable {

        public URLTable(TableModel tableModel) {
            super(tableModel);
            setupPopupMenu(); // 在构造函数中调用
        }
        private void setupPopupMenu() {
            JPopupMenu popupMenu = new JPopupMenu();

            JMenuItem clearAll = new JMenuItem("Clear All");
            clearAll.addActionListener(e -> {
                ((InitiativeScan.URLTableModel) getModel()).clearData();
            });

            JMenuItem deleteRow = new JMenuItem("Delete Selected Row");
            deleteRow.addActionListener(e -> {
                int selectedRow = getSelectedRow();
                if (selectedRow != -1) {
                    ((InitiativeScan.URLTableModel) getModel()).removeRow(selectedRow);
                }
            });

            popupMenu.add(clearAll);
            popupMenu.add(deleteRow);
            this.setComponentPopupMenu(popupMenu);
        }

        //选中表格中的某一行
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
//            InitiativeScan.TablesData dataEntry = InitiativeScan.this.Udatas.get(convertRowIndexToModel(row));
//            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
//            HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
//            currentlyDisplayedItem = dataEntry.requestResponse;
//            super.changeSelection(row, col, toggle, extend);
            super.changeSelection(row, col, toggle, extend);
            // 从模型中获取当前行的数据
            URLTableModel model = (URLTableModel) getModel();
            TablesData dataEntry = model.Udatas.get(convertRowIndexToModel(row));

            if (dataEntry != null && dataEntry.requestResponse != null) {
                HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
                currentlyDisplayedItem = dataEntry.requestResponse;
            }
        }
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

    @Override
    public String getTabCaption() {
        return null;
    }

    @Override
    public Component getUiComponent() {
        return null;
    }
}
