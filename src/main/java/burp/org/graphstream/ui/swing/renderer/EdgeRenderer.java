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
  
package burp.org.graphstream.ui.swing.renderer;

import org.graphstream.ui.graphicGraph.GraphicEdge;
import org.graphstream.ui.graphicGraph.GraphicElement;
import org.graphstream.ui.graphicGraph.StyleGroup;
import burp.org.graphstream.ui.swing.Backend;
import org.graphstream.ui.view.camera.DefaultCamera2D;
import burp.org.graphstream.ui.swing.SwingGraphRenderer;
import burp.org.graphstream.ui.swing.renderer.shape.Connector;
import burp.org.graphstream.ui.swing.renderer.shape.Shape;
import burp.org.graphstream.ui.swing.renderer.shape.swing.baseShapes.AreaOnConnectorShape;

public class EdgeRenderer extends StyleRenderer {	
	private Shape shape = null;
	AreaOnConnectorShape arrow = null;
			
	public EdgeRenderer(StyleGroup styleGroup) {
		super(styleGroup);
	}
	
	public EdgeRenderer(StyleGroup styleGroup, SwingGraphRenderer mainRenderer) {
		super(styleGroup);
	}

	@Override
	public void setupRenderingPass(Backend bck, DefaultCamera2D camera, boolean forShadow) {
		shape = bck.chooseEdgeShape(shape, group);
		arrow = (AreaOnConnectorShape)bck.chooseEdgeArrowShape(arrow, group);
	}

	@Override
	public void pushStyle(Backend bck, DefaultCamera2D camera, boolean forShadow) {
		shape.configureForGroup(bck, group, camera);
		
		if(arrow != null) {
			arrow.configureForGroup(bck, group, camera);
		}
	}

	@Override
	public void pushDynStyle(Backend bck, DefaultCamera2D camera, GraphicElement element) {}

	@Override
	public void renderElement(Backend bck, DefaultCamera2D camera, GraphicElement element) {
		GraphicEdge edge = (GraphicEdge)element;
		ConnectorSkeleton skel = getOrSetConnectorSkeleton(element);
		
		shape.configureForElement(bck, element, skel, camera);
		shape.render(bck, camera, element, skel);
		  
		if(edge.isDirected() && (arrow != null)) {
			arrow.theConnectorYoureAttachedTo((Connector)shape /* !!!! Test this TODO ensure this !!! */);
			arrow.configureForElement(bck, element, skel, camera);
		  	arrow.render(bck, camera, element, skel);
		}
	}

	@Override
	public void renderShadow(Backend bck, DefaultCamera2D camera, GraphicElement element) {
		GraphicEdge edge = (GraphicEdge)element;
		ConnectorSkeleton skel = getOrSetConnectorSkeleton(element);
				
		shape.configureForElement(bck, element, skel, camera);
		shape.renderShadow(bck, camera, element, skel);
  
		if(edge.isDirected() && (arrow != null)) {
			arrow.theConnectorYoureAttachedTo((Connector)shape /* !!!! Test this TODO ensure this !!! */);
			arrow.configureForElement(bck, element, skel, camera);
			arrow.renderShadow(bck, camera, element, skel);
		}
	}
	
	/** Retrieve the shared edge informations stored on the given edge element.
	  * If such information is not yet present, add it to the element. 
	  * @param element The element to look for.
	  * @return The edge information.
	  * @throws RuntimeException if the element is not an edge. */
	protected ConnectorSkeleton getOrSetConnectorSkeleton(GraphicElement element) {
		if(element instanceof GraphicEdge) {
			ConnectorSkeleton info = (ConnectorSkeleton)element.getAttribute(Skeleton.attributeName) ;
			
			if(info == null) {
				info = new ConnectorSkeleton();
				element.setAttribute(Skeleton.attributeName, info);
			}
			
			return info;
		}
		else {
			throw new RuntimeException("Trying to get EdgeInfo on non-edge...");
		}
	}
	
	@Override
	public void elementInvisible(Backend bck, DefaultCamera2D camera, GraphicElement element) {}
	
	@Override
	public void endRenderingPass(Backend bck, DefaultCamera2D camera, boolean forShadow) {}
}
