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
  
package burp.org.graphstream.ui.swing.renderer.shape.swing.basicShapes;

import java.awt.geom.RoundRectangle2D;

import burp.org.graphstream.ui.swing.Backend;
import org.graphstream.ui.view.camera.DefaultCamera2D;
import burp.org.graphstream.ui.swing.renderer.shape.swing.baseShapes.RectangularAreaShape;

public class RoundedSquareShape extends RectangularAreaShape {
	RoundRectangle2D.Double theShape = new RoundRectangle2D.Double();
	
	@Override
	public void make(Backend backend, DefaultCamera2D camera) {
		double w = area.theSize.x ;
		double h = area.theSize.x ;
		double r = h/8 ;
		if( h/8 > w/8 )
			r = w/8 ;
		((RoundRectangle2D) theShape()).setRoundRect( area.theCenter.x-w/2, area.theCenter.y-h/2, w, h, r, r ) ;
	}
	
	@Override
	public void makeShadow(Backend backend, DefaultCamera2D camera) {
		double x = area.theCenter.x + shadowable.theShadowOff.x;
		double y = area.theCenter.y + shadowable.theShadowOff.y;
		double w = area.theSize.x + shadowable.theShadowWidth.x * 2;
		double h = area.theSize.y + shadowable.theShadowWidth.y * 2;
		double r = h/8 ;
		if( h/8 > w/8 ) 
			r = w/8;
				
		((RoundRectangle2D) theShape()).setRoundRect( x-w/2, y-h/2, w, h, r, r );
	}
	
	@Override
	public java.awt.geom.RectangularShape theShape() {
		return theShape;
	}
}