/*
 * This file is part of GraphStream <http://graphstream-project.org>.
 * 
 * GraphStream is a library whose purpose is to handle static or dynamic
 * graph, create them from scratch, file or any source and display them.
 * 
 * This program is free software distributed under the terms of two licenses, the
 * CeCILL-C license that fits European law, and the GNU Lesser General Public
 * License. You can  use, modify and/ or redistribute the software under the terms
 * of the CeCILL-C license as circulated by CEA, CNRS and INRIA at the following
 * URL <http://www.cecill.info> or under the terms of the GNU LGPL as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C and LGPL licenses and that you accept their terms.
 */

 /**
  * @author Antoine Dutot <antoine.dutot@graphstream-project.org>
  * @author Guilhelm Savin <guilhelm.savin@graphstream-project.org>
  * @author Hicham Brahimi <hicham.brahimi@graphstream-project.org>
  */
  
package burp.org.graphstream.ui.swing_viewer;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Timer;

import org.graphstream.graph.Graph;
import org.graphstream.stream.ProxyPipe;
import org.graphstream.stream.Source;
import org.graphstream.stream.thread.ThreadProxyPipe;
import org.graphstream.ui.graphicGraph.GraphicGraph;
import burp.org.graphstream.ui.swing.SwingGraphRenderer;
import org.graphstream.ui.view.GraphRenderer;
import org.graphstream.ui.view.View;
import org.graphstream.ui.view.Viewer;

/**
 * Set of views on a graphic graph.
 * 
 * <p>
 * The viewer class is in charge of maintaining :
 * <ul>
 * <li>A "graphic graph" (a special graph that internally stores the graph under
 * the form of style sets of "graphic" elements, suitable to draw the graph, but
 * not to adapted to used it as a general graph),</li>
 * <li>The eventual proxy pipe from which the events come from (but graph events
 * can come from any kind of source),</li>
 * <li>A default view, and eventually more views on the graphic graph.</li>
 * <li>A flag that allows to repaint the view only if the graphic graph changed.
 * <li>
 * </ul>
 * </p>
 * 
 * <p>
 * The graphic graph can be created by the viewer or given at construction (to
 * share it with another viewer).
 * </p>
 * 
 * <p>
 * <u>Once created, the viewer runs in a loop inside the Swing thread. You
 * cannot call methods on it directly if you are not in this thread</u>. The
 * only operation that you can use in other threads is the constructor, the
 * {@link #addView(View)}, {@link #removeView(String)} and the {@link #close()}
 * methods. Other methods are not protected from concurrent accesses.
 * </p>
 * 
 * <p>
 * Some constructors allow a {@link ProxyPipe} as argument. If given, the
 * graphic graph is made listener of this pipe and the pipe is "pumped" during
 * the view loop. This allows to run algorithms on a graph in the main thread
 * (or any other thread) while letting the viewer run in the swing thread.
 * </p>
 * 
 * <p>
 * Be very careful: due to the nature of graph events in GraphStream, the viewer
 * is not aware of events that occured on the graph <u>before</u> its creation.
 * There is a special mechanism that replay the graph if you use a proxy pipe or
 * if you pass the graph directly. However, when you create the viewer by
 * yourself and only pass a {@link Source}, the viewer <u>will not</u> display
 * the events that occured on the source before it is connected to it.
 * </p>
 */
public class SwingViewer extends Viewer implements ActionListener {

	// Attributes

	/**
	 * Timer in the Swing thread.
	 */
	protected Timer timer ;

	/**
	 * Delay in milliseconds between frames.
	 */
	protected int delay = 40;
	
	/**
	 * Name of the default view.
	 */
	public static String DEFAULT_VIEW_ID = "defaultView";

	public String getDefaultID() {
		return DEFAULT_VIEW_ID ;
	}
	
	// Construction

	/**
	 * The graph or source of graph events is in another thread or on another
	 * machine, but the pipe already exists. The graphic graph displayed by this
	 * viewer is created.
	 * 
	 * @param source
	 *            The source of graph events.
	 */
	public SwingViewer(ProxyPipe source) {
		graphInAnotherThread = true;
		init(new GraphicGraph(newGGId()), source, (Source) null);
	}

	/**
	 * We draw a pre-existing graphic graph. The graphic graph is maintained by
	 * its creator.
	 * 
	 * @param graph
	 *            THe graph to draw.
	 */
	public SwingViewer(GraphicGraph graph) {
		graphInAnotherThread = false;
		init(graph, (ProxyPipe) null, (Source) null);
	}

	/**
	 * New viewer on an existing graph. The viewer always run in the Swing
	 * thread, therefore, you must specify how it will take graph events from
	 * the graph you give. If the graph you give will be accessed only from the
	 * Swing thread use ThreadingModel.GRAPH_IN_GUI_THREAD. If the graph you use
	 * is accessed in another thread use ThreadingModel.GRAPH_IN_ANOTHER_THREAD.
	 * This last scheme is more powerful since it allows to run algorithms on
	 * the graph in parallel with the viewer.
	 * 
	 * @param graph
	 *            The graph to render.
	 * @param threadingModel
	 *            The threading model.
	 */
	public SwingViewer(Graph graph, ThreadingModel threadingModel) {
		switch (threadingModel) {
		case GRAPH_IN_GUI_THREAD:
			graphInAnotherThread = false;
			init(new GraphicGraph(newGGId()), (ProxyPipe) null, graph);
			enableXYZfeedback(true);
			break;
		case GRAPH_IN_ANOTHER_THREAD:
			graphInAnotherThread = true;

			ThreadProxyPipe tpp = new ThreadProxyPipe();
			tpp.init(graph, true);

			init(new GraphicGraph(newGGId()), tpp, (Source) null);
			enableXYZfeedback(false);
			break;
		case GRAPH_ON_NETWORK:
			throw new RuntimeException("TO DO, sorry !:-)");
		}
	}

	/**
	 * Initialise the viewer.
	 * 
	 * @param graph
	 *            The graphic graph.
	 * @param ppipe
	 *            The source of events from another thread or machine (null if
	 *            source != null).
	 * @param source
	 *            The source of events from this thread (null if ppipe != null).
	 */
	public void init(GraphicGraph graph, ProxyPipe ppipe, Source source) {
		this.graph = graph;
		this.pumpPipe = ppipe;
		this.sourceInSameThread = source;

		this.timer = new Timer(delay, this);
		
		assert ((ppipe != null && source == null) || (ppipe == null && source != null));

		if (pumpPipe != null)
			pumpPipe.addSink(graph);
		if (sourceInSameThread != null) {
			if (source instanceof Graph)
				replayGraph((Graph) source);
			sourceInSameThread.addSink(graph);
		}
		
		timer.setCoalesce(true);
		timer.setRepeats(true);
		timer.start();
	}

	/**
	 * Close definitively this viewer and all its views.
	 */
	public void close() {
		synchronized (views) {
			disableAutoLayout();

			for (View view : views.values())
				view.close(graph);

			timer.removeActionListener(this);

			if (pumpPipe != null)
				pumpPipe.removeSink(graph);
			if (sourceInSameThread != null)
				sourceInSameThread.removeSink(graph);

			graph = null;
			pumpPipe = null;
			sourceInSameThread = null;
			timer = null;
		}
	}

	// Access

	/**
	 * Create a new instance of the default graph renderer.
	 */
	public GraphRenderer<?, ?> newDefaultGraphRenderer() {
		return new SwingGraphRenderer();
	}

	// Command
	
	/**
	 * Build the default graph view and insert it. The view identifier is
	 * {@link #DEFAULT_VIEW_ID}. You can request the view to be open in its own
	 * frame.
	 * 
	 * @param renderer
	 * @param openInAFrame
	 *            It true, the view is placed in a frame, else the view is only
	 *            created and you must embed it yourself in your application.
	 */
	public View addDefaultView(boolean openInAFrame, GraphRenderer<?, ?> renderer) {
		synchronized (views) {
			View view = renderer.createDefaultView(this, getDefaultID());
			
			addView(view);
			
			if (openInAFrame)
				view.openInAFrame(true);

			return view;
		}
	}

	/**
	 * Called on a regular basis by the timer. Checks if some events occurred
	 * from the graph pipe or from the layout pipe, and if the graph changed,
	 * triggers a repaint. Never call this method, it is called by a Swing Timer
	 * automatically.
	 */
	@Override
	public void actionPerformed(ActionEvent arg0) {
		// TODO Auto-generated method stub
		synchronized (views) {
			// long t1=System.currentTimeMillis();
			// long gsize1=graph.getNodeCount();
			if (pumpPipe != null)
				pumpPipe.pump();
			// long gsize2=graph.getNodeCount();
			// long t2=System.currentTimeMillis();

			if (layoutPipeIn != null)
				layoutPipeIn.pump();
			// long t3=System.currentTimeMillis();
			// Prevent the timer from using a empty graph to display
			if(graph != null){
				boolean changed = graph.graphChangedFlag();

				if (changed) {
					computeGraphMetrics();
					// long t4=System.currentTimeMillis();

					for (View view : views.values())
						view.display(graph, changed);
				}
				// long t5=System.currentTimeMillis();

				graph.resetGraphChangedFlag();
			}
			// System.err.printf("display pump=%f layoutPump=%f metrics=%f
			// display=%f (size delta=%d size1=%d size2=%d)%n",
			// (t2-t1)/1000.0, (t3-t2)/1000.0, (t4-t3)/1000.0, (t5-t4)/1000.0,
			// (gsize2-gsize1), gsize1, gsize2);
		}
	}
}
