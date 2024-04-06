package burp;

//import burp.IBurpExtenderCallbacks;
import burp.IBurpExtenderCallbacks;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Event;
//import java.awt.AWTEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import javax.swing.JComboBox;
import javax.swing.JPanel;
import org.graphstream.graph.Graph;
import org.graphstream.graph.implementations.SingleGraph;
import org.graphstream.ui.layout.springbox.implementations.SpringBox;
import org.graphstream.ui.swing.SwingGraphRenderer;
import org.graphstream.ui.swing_viewer.DefaultView;
import org.graphstream.ui.swing_viewer.SwingViewer;
import org.graphstream.ui.swing_viewer.ViewPanel;
import org.graphstream.ui.view.Viewer;
//import org.graphstream.ui.swing.SwingGraphRenderer;

public class GraphFrameComponent extends javax.swing.JPanel {
    IBurpExtenderCallbacks mCallbacks;
    Graph graph;
    ZoomPanPanel zp = new ZoomPanPanel();
    
    /**
     * Creates new form BurpSuiteTab
     * @param callbacks   For UI Look and Feel
     */
    public GraphFrameComponent(IBurpExtenderCallbacks callbacks) {
        mCallbacks = callbacks;
        System.setProperty("org.graphstream.ui", "swing");
        
        graph = new SingleGraph("Tutorial 1");
        graph.setAttribute("ui.stylesheet", "node{\n" +
        "    size: 30px, 30px;\n" +
        "    fill-color: #f7f7f0;\n" +
        "    text-mode: normal; \n" +
        "}");
                
//        graph.addNode("A").setAttribute("ui.label", "A");
//        graph.addNode("B").setAttribute("ui.label", "B");
//        graph.addNode("C").setAttribute("ui.label", "C");
//        graph.addEdge("AB", "A", "B").setAttribute("ui.label", "A --> B");
//        graph.addEdge("BC", "B", "C").setAttribute("ui.label", "B --> C");
//        graph.addEdge("CA", "C", "A").setAttribute("ui.label", "C --> A");


	initComponents();
        


    Viewer viewer1 = new SwingViewer(graph, Viewer.ThreadingModel.GRAPH_IN_GUI_THREAD);
    viewer1.enableAutoLayout(new SpringBox());
    ViewPanel viewPanel1 = new DefaultView(viewer1,"panel1",new SwingGraphRenderer());
    viewPanel1.setPreferredSize(new Dimension(900,900));
    
            //add a mouse wheel listener to the ViewPanel for zooming the graph
//        viewPanel1.addMouseWheelListener(new MouseWheelListener() {
//            @Override
//            public void mouseWheelMoved(MouseWheelEvent mwe) {
//                
//                zoomGraph.zoomGraphMouseWheelMoved(mwe, viewPanel1);
//            }
//        });


    JPanel panel1 = new JPanel();
    panel1.setBackground(Color.gray);
    panel1.setLayout(new BorderLayout());
    panel1.setPreferredSize(new Dimension(900,900));
    panel1.add(viewPanel1,BorderLayout.CENTER);

    
    panel1.setBackground(Color.blue);

    JPanel graphPanel = new JPanel();
    graphPanel.setPreferredSize(new Dimension(1200, 800));
    graphPanel.setLayout(new BorderLayout(10,10));
    graphPanel.add(panel1,BorderLayout.WEST);

    JComboBox<String> lCCommunitiesNames = new JComboBox<>();
    lCCommunitiesNames.setPreferredSize(new Dimension(795,30));
    
    JPanel lCComboPanel = new JPanel();
    lCComboPanel.setLayout(new BorderLayout());
    lCComboPanel.add(lCCommunitiesNames,BorderLayout.CENTER);


    JComboBox<String> minoltaCommunitiesNames = new JComboBox<>();
    minoltaCommunitiesNames.setPreferredSize(new Dimension(795,30));
    JPanel minoltaComboPanel = new JPanel();
    minoltaComboPanel.setLayout(new BorderLayout());
    minoltaComboPanel.add(minoltaCommunitiesNames, BorderLayout.CENTER);

    JPanel selectorPanel = new JPanel();
    selectorPanel.setLayout(new BorderLayout(10,10));
    graphPanel.setPreferredSize(new Dimension(1200, 100));
    selectorPanel.add(lCComboPanel,BorderLayout.WEST);

    JPanel f = new JPanel();
//    f.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
    f.setSize(new Dimension(1200,800));
    f.setLayout(new BorderLayout(200,10));
    f.add(graphPanel,BorderLayout.WEST);
    f.add(selectorPanel,BorderLayout.SOUTH);
    jPanel1.add(f);
//    f.setVisible(true);
        
//     mCallbacks.customizeUiComponent(f);   
        
//        mCallbacks.customizeUiComponent(jRadioButtonInScopeRequests);
//        mCallbacks.customizeUiComponent(jRadioButtonAllRequests);
//        
//        buttonGroupDefineScope.add(jRadioButtonInScopeRequests);
//        buttonGroupDefineScope.add(jRadioButtonAllRequests);
        
//        restoreSavedSettings();
    }
    
    public void addComponent(JPanel customPanel) {
        JPanel newPanel = (JPanel)this.add(customPanel);
        this.doLayout();
        newPanel.setLocation(275,0);
    }
       //the methode that will zoom the graph
   public static void zoomGraphMouseWheelMoved(MouseWheelEvent mwe, ViewPanel view_panel){
        if (Event.ALT_MASK != 0) {            
            if (mwe.getWheelRotation() > 0) {
                double new_view_percent = view_panel.getCamera().getViewPercent() + 0.05;
                view_panel.getCamera().setViewPercent(new_view_percent);               
            } else if (mwe.getWheelRotation() < 0) {
                double current_view_percent = view_panel.getCamera().getViewPercent();
                if(current_view_percent > 0.05){
                    view_panel.getCamera().setViewPercent(current_view_percent - 0.05);                
                }
            }
        }                     
    }
    /**
     * Returns true if all response times should be calculated
     * @return true if the GUI indicates all requests should be processed
     */
    public boolean processAllRequests() {
        return false;
//        return jRadioButtonAllRequests.isSelected();
    }

    /**
     * Save all configured settings
     */
    public void saveSettings() {
        // Clear settings
        mCallbacks.saveExtensionSetting("O_SCOPE", null);

        // Set any selected checkboxes in settings
//        if(jRadioButtonAllRequests.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_SCOPE", "ALL");
//        }
    }
    
    public void addNode(String nodeName){
        if(graph.getNode(nodeName) == null){
            graph.addNode(nodeName).setAttribute("ui.label", nodeName);
        }        
    }
    
    public void addEdge(String httpVerb, String path1, String path2){
        if(graph.getEdge(httpVerb + " " + path1 + " " + path2) == null){
            graph.addEdge((httpVerb + " " + path1 + " " + path2), path1, path2, true).setAttribute("ui.label", httpVerb);
        }        
    }
    /**
     * Restores any found saved settings
     */
//    public void restoreSavedSettings() {
//        boolean scopeAllSel = false;
//        
//        if(mCallbacks.loadExtensionSetting("O_SCOPE") != null ) {
//            scopeAllSel = getSetting("O_SCOPE");
//        }
//        jRadioButtonAllRequests.setSelected(scopeAllSel);
//    }
    
    /**
     * Get the boolean value of the requested setting
     * @param name
     * @return whether the setting was selected
     */
//    private boolean getSetting(String name) {
//        if(name.equals("O_SCOPE") && mCallbacks.loadExtensionSetting(name).equals("ALL") == true) {
//            return true;
//        }
//        else return mCallbacks.loadExtensionSetting(name).equals("ENABLED") == true;
//    }
//

 
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroupDefineScope = new javax.swing.ButtonGroup();
        buttonGroupChars = new javax.swing.ButtonGroup();
        jPanel1 = new javax.swing.JPanel();

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 1405, Short.MAX_VALUE)
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGap(0, 901, Short.MAX_VALUE)
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(0, 0, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroupChars;
    private javax.swing.ButtonGroup buttonGroupDefineScope;
    private javax.swing.JPanel jPanel1;
    // End of variables declaration//GEN-END:variables

}
