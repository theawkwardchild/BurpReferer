package burp;

//import java.awt.Component;
//import burp.IHttpRequestResponse;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.graphstream.graph.implementations.SingleGraph;
//import burp.org.graphstream.graph.Graph;

import org.graphstream.graph.*;
//import org.graphstream.graph.implementations.SingleGraph;


public class BurpExtender extends BurpGUIExtender //implements IBurpExtender, ITab, IHttpListener
{

    Graph graph; // = new SingleGraph("Tutorial 1");
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
//        System.setProperty("org.graphstream.ui", "swing"); // gs-core needs to be told which UI implementation to use
        graph = new SingleGraph("Tutorial 1");
        init();
        mCallbacks = callbacks;
        mHelper = mCallbacks.getHelpers();

        callbacks.setExtensionName(mPluginName);
        mStdOut = new PrintWriter(callbacks.getStdout(), true);
        mStdErr = new PrintWriter(callbacks.getStderr(), true);

        callbacks.registerHttpListener(this); // For processHttpMessage
//        callbacks.registerExtensionStateListener(this); // For notification of unload extension

        toolsScope = new ToolsScopeComponent(mCallbacks);
        mCallbacks.customizeUiComponent(toolsScope);

        graphFrame = new GraphFrameComponent(mCallbacks);
        
        
        mCallbacks.customizeUiComponent(graphFrame);

        mTab = new BurpSuiteTab(mPluginName, mCallbacks);
        mTab.add(toolsScope);
        ZoomPanPanel zp = new ZoomPanPanel();
        zp.add(graphFrame);
        mTab.add(zp);

        mCallbacks.customizeUiComponent(mTab);
        mCallbacks.addSuiteTab(mTab);
        mStdOut.println("Settings for " + mPluginName + " can be edited in the " + mPluginName + " tab.");
        mStdOut.println(mUsageStatement);
        
        
//        graph.addNode("A" );
//        graph.addNode("B" );
//        graph.addNode("C" );
//        graph.addEdge("AB", "A", "B");
//        graph.addEdge("BC", "B", "C");
//        graph.addEdge("CA", "C", "A");
//        graph.display();


    }
//    @Override
//    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
//    {
//    }

    @Override
    public String getTabCaption() {
        return "Referer Map";
    }

//    @Override
//    public Component getUiComponent() {
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//    }
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
//         mStdOut.println("BurpExtener -> processHttpMessage...");

        if (messageIsRequest) {
            return;
        }

        String request = new String(messageInfo.getRequest());
        String response = new String(messageInfo.getResponse());
        

//        mStdOut.println(request);
//        mStdOut.println(response);
//        request.split("\r?\n\r?\n");
//        String requestHeaders = request.split("\n\n")[0];
//        String responseHeaders= response.split("\n\n")[0];
        String httpVerb = request.split(" ", 2)[0];
        String requestUri = request.split(" ")[1].split("\\?")[0];
        String[] skippedExtensions = new String[]
        {
            ".png", ".jpg", ".jpeg", 
            ".ico", ".ttf", ".woff", 
            ".woff2", ".svg", ".gif", 
            ".css", ".mp3", ".mp4",
        };
        
        for (int i = 0; i < skippedExtensions.length; i++) {
            if(requestUri.endsWith(skippedExtensions[i])){
                return;
            }            
        }
//        int statusCode = Integer.parseInt(responseHeaders.split(" ", 2)[1]);
        
        Pattern refererHeaderPattern = Pattern.compile("Referer: .*");
        Matcher matcher = refererHeaderPattern.matcher(request);
        Boolean hasReferer = matcher.find(); // need a fail case for when it is a direct browse w/ no referer
        String referer = matcher.group().split(" ")[1].split("\\?")[0]; 
//        Map<String, String> queryParameters = new HashMap<String, String>();
//        mStdOut.println("[+] request: " + request);
//        mStdOut.println("[+] responseHeaders: " + responseHeaders);
        mStdOut.println("[+] httpVerb: " + httpVerb);
        mStdOut.println("[+] requestUri: " + requestUri);
//        mStdOut.println("[+] statusCode: " + statusCode);
//        mStdOut.println("[+] hasReferer: " + hasReferer);
        mStdOut.println("[+] node1: " + referer);
        String refererUri;
        Pattern hostPattern = Pattern.compile("https?:\\/\\/[^\\/]*");
        Matcher hostMatcher = hostPattern.matcher(referer);
        hostMatcher.find();
        String host = hostMatcher.group().split("\\?")[0];
        mStdOut.println("[+] node2: " + host + requestUri);
        try{
            graphFrame.addNode(referer);
            graphFrame.addNode(host + requestUri);
            graphFrame.addEdge(httpVerb, referer, host + requestUri);
            
        } catch(Exception e){
            System.out.println("ERROR!\n" + e);
        }
        mStdOut.println("------------------------------------\n\n");
        
    }
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody

    @Override
    protected void init() {
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
        mPluginName = "Burp Referer";
    }

//    @Override
//    protected IHttpRequestResponse processSelectedMessage(IHttpRequestResponse messageInfo, boolean isRequest) {
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//    }
}
