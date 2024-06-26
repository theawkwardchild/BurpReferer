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
  
package burp.org.graphstream.ui.swing.renderer.shape.swing.arrowShapes;

import java.awt.Graphics2D;
import java.awt.geom.Path2D;

import org.graphstream.ui.geom.Point2;
import org.graphstream.ui.geom.Vector2;
import org.graphstream.ui.graphicGraph.GraphicElement;
import org.graphstream.ui.graphicGraph.stylesheet.Style;
import burp.org.graphstream.ui.swing.Backend;
import org.graphstream.ui.view.camera.DefaultCamera2D;
import burp.org.graphstream.ui.swing.renderer.Skeleton;
import burp.org.graphstream.ui.swing.renderer.shape.swing.baseShapes.AreaOnConnectorShape;
import burp.org.graphstream.ui.swing.util.CubicCurve;
import burp.org.graphstream.ui.swing.util.ShapeUtil;
import burp.org.graphstream.ui.swing.util.AttributeUtils.Tuple;

public class DiamondOnEdge extends AreaOnConnectorShape {
	Path2D.Double theShape = new Path2D.Double();
	
	@Override
	public void make(Backend backend, DefaultCamera2D camera) {
		make( false, camera );
	}

	@Override
	public void makeShadow(Backend backend, DefaultCamera2D camera) {
		make( true, camera );
	}

	private void make(boolean forShadow, DefaultCamera2D camera) {
		if( theConnector.skel.isCurve() )
			makeOnCurve( forShadow, camera );
		else
			makeOnLine(  forShadow, camera );
	}
	

	private void makeOnCurve(boolean forShadow, DefaultCamera2D camera) {
		Tuple<Point2, Double> tuple = CubicCurve.approxIntersectionPointOnCurve( theEdge, theConnector, camera );

		Point2 p1 = tuple.x ;
		double t = tuple.y ;
		
		Style style  = theEdge.getStyle();
				
		Point2 p2  = CubicCurve.eval( theConnector.fromPos(), theConnector.byPos1(), theConnector.byPos2(), theConnector.toPos(), t-0.1f );
		Vector2 dir = new Vector2( p1.x - p2.x, p1.y - p2.y );
		dir.normalize();
		dir.scalarMult( theSize.x );
		Vector2 per = new Vector2( dir.y(), -dir.x() );
		per.normalize();
		per.scalarMult( theSize.y );
		
		// Create a polygon.
		
		theShape.reset();
		theShape.moveTo( p1.x , p1.y );
		theShape.lineTo( p1.x - dir.x()/2 + per.x(), p1.y - dir.y()/2 + per.y() );
		theShape.lineTo( p1.x - dir.x(), p1.y - dir.y() );
		theShape.lineTo( p1.x - dir.x()/2 - per.x(), p1.y - dir.y()/2 - per.y() );
		theShape.closePath();
	}

	private void makeOnLine(boolean forShadow, DefaultCamera2D camera) {
		double off = ShapeUtil.evalTargetRadius2D( theEdge, camera );
		Vector2 theDirection = new Vector2(
			theConnector.toPos().x - theConnector.fromPos().x,
			theConnector.toPos().y - theConnector.fromPos().y );
			
		theDirection.normalize();
  
		double x = theCenter.x - ( theDirection.x() * off );
		double y = theCenter.y - ( theDirection.y() * off );
		Vector2 perp = new Vector2( theDirection.y(), -theDirection.x() );
		
		perp.normalize();
		theDirection.scalarMult( theSize.x / 2 );
		perp.scalarMult( theSize.y );
		
		if( forShadow ) {
			x += shadowable.theShadowOff.x;
			y += shadowable.theShadowOff.y;
		}
  
		// Create a polygon.
		
		theShape.reset();
		theShape.moveTo( x , y );
		theShape.lineTo( x - theDirection.x() + perp.x(), y - theDirection.y() + perp.y() );	
		theShape.lineTo( x - theDirection.x()*2, y - theDirection.y()*2 );
		theShape.lineTo( x - theDirection.x() - perp.x(), y - theDirection.y() - perp.y() );
		theShape.closePath();
	}

	@Override
	public void render(Backend bck, DefaultCamera2D camera, GraphicElement element, Skeleton skeleton) {
		Graphics2D g = bck.graphics2D();
		make( false, camera );
		strokable.stroke( g, theShape );
		fillable.fill( g, theShape, camera );
	}

	@Override
	public void renderShadow(Backend bck, DefaultCamera2D camera, GraphicElement element, Skeleton skeleton) {
		make( true, camera );
		shadowable.cast(bck.graphics2D(), theShape );
	}
}