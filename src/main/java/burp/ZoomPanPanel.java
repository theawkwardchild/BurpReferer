package burp;


import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.geom.AffineTransform;

import javax.swing.JPanel;

public class ZoomPanPanel extends JPanel implements MouseWheelListener, MouseMotionListener {

  private AffineTransform transform = new AffineTransform(); // Stores the transformation for zoom and pan
  private Point startDrag; // Point where dragging for panning starts

  public ZoomPanPanel() {
    addMouseWheelListener(this);
    addMouseMotionListener(this);
    
    
  }

  @Override
  public void paintComponent(Graphics g) {
    super.paintComponent(g);
    Graphics2D g2d = (Graphics2D) g;
    g2d.transform(transform);  // Apply transformation to drawing
    // Your drawing code here (assuming you have something to draw)
  }

  @Override
  public void mouseWheelMoved(MouseWheelEvent e) {
    int zoomDirection = e.getWheelRotation();
    double zoomFactor = zoomDirection > 0 ? 1.1 : 0.9; // Adjust zoom factor as needed
    Point center = new Point(getWidth() / 2, getHeight() / 2); // Zoom around the center

    transform.translate(center.x, center.y);
    transform.scale(zoomFactor, zoomFactor);
    transform.translate(-center.x, -center.y);

    repaint();
  }

  @Override
  public void mouseDragged(MouseEvent e) {
    if (startDrag != null) {
      double dx = e.getX() - startDrag.getX();
      double dy = e.getY() - startDrag.getY();
      transform.translate(dx, dy);
      repaint();
    }
  }

//  @Override
  public void mousePressed(MouseEvent e) {
    startDrag = e.getPoint();
  }

//  @Override
  public void mouseReleased(MouseEvent e) {
    startDrag = null;
  }

  @Override
  public void mouseMoved(MouseEvent e) {
    // Handle hover effects or other mouse movements if needed
  }
}