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
  
package burp.org.graphstream.ui.swing.renderer.shape.swing.shapePart;

import java.awt.Color;
import java.awt.Graphics2D;

import org.graphstream.ui.graphicGraph.stylesheet.Style;
import org.graphstream.ui.view.camera.DefaultCamera2D;
import burp.org.graphstream.ui.swing.renderer.shape.swing.ShapeStroke;

public class Strokable {
    /** The stroke color. */
	public Color strokeColor = null ;

	/** The stroke. */
	public ShapeStroke theStroke = null ;
 	
	/** The stroke width. */
	public double theStrokeWidth = 0.0 ;

 	/** Paint the stroke of the shape. */
	public void stroke( Graphics2D g, java.awt.Shape shape ) {
		if(theStroke != null) {
			g.setStroke( theStroke.stroke( theStrokeWidth ) );
			g.setColor( strokeColor );
			g.draw( shape );
		}	  
	}
	
 	/** Configure all the static parts needed to stroke the shape. */
 	public void configureStrokableForGroup( Style style, DefaultCamera2D camera ) {
		theStrokeWidth = camera.getMetrics().lengthToGu( style.getStrokeWidth() );
		/*if( strokeColor == null )*/ strokeColor = ShapeStroke.strokeColor( style );
		/*if( theStroke   == null )*/ theStroke   = ShapeStroke.strokeForArea( style );
 	}
}