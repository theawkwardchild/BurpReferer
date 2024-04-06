package burp;

import burp.IBurpExtenderCallbacks;
import burp.IBurpExtenderCallbacks;

public class ToolsScopeComponent extends javax.swing.JPanel {

    IBurpExtenderCallbacks mCallbacks;

    /**
     * Creates new form BurpSuiteTab
     *
     * @param customPanel The panel to be added to the GUI
     * @param tabName The name displayed on the tab
     * @param callbacks For UI Look and Feel
     */
    public ToolsScopeComponent(IBurpExtenderCallbacks callbacks) {
        mCallbacks = callbacks;

        //this.doLayout();
        
        initComponents();

//        mCallbacks.customizeUiComponent(jCheckBoxProxy);
//        mCallbacks.customizeUiComponent(jCheckBoxRepeater);
//        mCallbacks.customizeUiComponent(jCheckBoxScanner);
//        mCallbacks.customizeUiComponent(jCheckBoxIntruder);
//        mCallbacks.customizeUiComponent(jCheckBoxSequencer);
//        mCallbacks.customizeUiComponent(jCheckBoxSpider);

        restoreSavedSettings();
    }

    /**
     * Allows the enabling/disabling of UI tool selection elements, not every
     * tool makes sense for every extension
     *
     * @param tool
     * @param enabled
     */
    public void setEnabledToolConfig(int tool, boolean enabled) {
//        switch (tool) {
//            case IBurpExtenderCallbacks.TOOL_PROXY:
//                jCheckBoxProxy.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_REPEATER:
//                jCheckBoxRepeater.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_SCANNER:
//                jCheckBoxScanner.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_INTRUDER:
//                jCheckBoxIntruder.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
//                jCheckBoxSequencer.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_SPIDER:
//                jCheckBoxSpider.setEnabled(enabled);
//                break;
//            case IBurpExtenderCallbacks.TOOL_TARGET:
//                break;
//            default:
//                break;
//        }
    }

    /**
     * Returns true if the requested tool is selected in the GUI
     *
     * @param tool
     * @return whether the selected tool is selected
     */
    public boolean isToolSelected(int tool) {
        boolean selected = false;
//        switch (tool) {
//            case IBurpExtenderCallbacks.TOOL_PROXY:
//                selected = jCheckBoxProxy.isSelected() && jCheckBoxProxy.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_REPEATER:
//                selected = jCheckBoxRepeater.isSelected() && jCheckBoxRepeater.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_SCANNER:
//                selected = jCheckBoxScanner.isSelected() && jCheckBoxScanner.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_INTRUDER:
//                selected = jCheckBoxIntruder.isSelected() && jCheckBoxIntruder.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_SEQUENCER:
//                selected = jCheckBoxSequencer.isSelected() && jCheckBoxSequencer.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_SPIDER:
//                selected = jCheckBoxSpider.isSelected() && jCheckBoxSpider.isEnabled();
//                break;
//            case IBurpExtenderCallbacks.TOOL_TARGET:
//                break;
//            default:
//                break;
//        }
        return selected;
    }

    /**
     * Save all configured settings
     */
    public void saveSettings() {
        // Clear settings
        mCallbacks.saveExtensionSetting("O_TOOL_PROXY", null);
        mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", null);
        mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", null);
        mCallbacks.saveExtensionSetting("O_SCOPE", null);
        // Set any selected checkboxes in settings
//        if (jCheckBoxProxy.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_PROXY", "ENABLED");
//        }
//        if (jCheckBoxRepeater.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_REPEATER", "ENABLED");
//        }
//        if (jCheckBoxScanner.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_SCANNER", "ENABLED");
//        }
//        if (jCheckBoxIntruder.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_INTRUDER", "ENABLED");
//        }
//        if (jCheckBoxSequencer.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_SEQUENCER", "ENABLED");
//        }
//        if (jCheckBoxSpider.isSelected()) {
//            mCallbacks.saveExtensionSetting("O_TOOL_SPIDER", "ENABLED");
//        }
    }

    /**
     * Restores any found saved settings
     */
    public void restoreSavedSettings() {
        boolean proxySel = false;
        boolean repeaterSel = false;
        boolean scannerSel = false;
        boolean intruderSel = false;
        boolean sequencerSel = false;
        boolean spiderSel = false;

        if (mCallbacks.loadExtensionSetting("O_TOOL_PROXY") != null) {
            proxySel = getSetting("O_TOOL_PROXY");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_REPEATER") != null) {
            repeaterSel = getSetting("O_TOOL_REPEATER");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_SCANNER") != null) {
            scannerSel = getSetting("O_TOOL_SCANNER");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_INTRUDER") != null) {
            intruderSel = getSetting("O_TOOL_INTRUDER");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_SEQUENCER") != null) {
            sequencerSel = getSetting("O_TOOL_SEQUENCER");
        }
        if (mCallbacks.loadExtensionSetting("O_TOOL_SPIDER") != null) {
            spiderSel = getSetting("O_TOOL_SPIDER");
        }

//        jCheckBoxProxy.setSelected(proxySel);
//        jCheckBoxRepeater.setSelected(repeaterSel);
//        jCheckBoxScanner.setSelected(scannerSel);
//        jCheckBoxIntruder.setSelected(intruderSel);
//        jCheckBoxSequencer.setSelected(sequencerSel);
//        jCheckBoxSpider.setSelected(spiderSel);
    }

    /**
     * Get the boolean value of the requested setting
     *
     * @param name
     * @return whether the setting was selected
     */
    private boolean getSetting(String name) {
        if (name.equals("O_SCOPE") && mCallbacks.loadExtensionSetting(name).equals("ALL") == true) {
            return true;
        } else {
            return mCallbacks.loadExtensionSetting(name).equals("ENABLED") == true;
        }
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel3 = new javax.swing.JLabel();

        jLabel3.setFont(new java.awt.Font("Tahoma", 1, 13)); // NOI18N
        jLabel3.setForeground(new java.awt.Color(229, 137, 0));

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel3)
                .addContainerGap(245, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap(140, Short.MAX_VALUE)
                .addComponent(jLabel3))
        );
    }// </editor-fold>//GEN-END:initComponents

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel3;
    // End of variables declaration//GEN-END:variables

}
