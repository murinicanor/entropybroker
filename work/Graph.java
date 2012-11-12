package com.vanheusden.GoudaWeer;

import java.text.SimpleDateFormat;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.DashPathEffect;
import android.graphics.Paint;
import android.graphics.Rect;
import android.view.View;

public class Graph extends View {
	private String jsonData = null;
	private String url = null;
	private int w = -1, h = -1;
	private String header = null;
	
	public Graph(Context context) {
		super(context);
	}
	
	public Graph(Context context, int w, int h) {
		super(context);
		this.w = w;
		this.h = h;
	}

	protected void onSizeChanged (int w, int h, int oldw, int oldh) {
	}

	public void setHeader(String header) {
		this.header = header;
	}

	public void setData(String data) {
		jsonData = data;
	}
	
	public void setUrl(String url) {
		this.url = url;
	}
	
	public Rect getTextWidth(Paint p, String str) {
		Rect bounds = new Rect();
		
		p.getTextBounds(str, 0, str.length(), bounds);
		
		return bounds;
	}
	
	@Override
	protected void onDraw(Canvas canvas) {
		if (jsonData == null) {
			canvas.drawColor(Color.GRAY);
			return;
		}

		final int width = w != -1 ? w : getWidth();
		final int height = h != -1 ? h : getHeight();
		System.out.println("width: " + width + ", height: " + height);
		final int yAxisTop = header != null ? 12 : 5;
		final int yAxisBottom = height - 25;
		final int yTicks = 10;
		final int xTicks;
		final int yAxisMaxStrLen = 5;
		final int xAxisLeft;
		final int xAxisRight = width - 5;
		Paint f = new Paint();
		f.setTextSize(10);
		f.setAntiAlias(true);
		f.setColor(Color.BLACK);

		// determine x-position of y-axis
        String dummy = "";
        for(int nr=0; nr<yAxisMaxStrLen; nr++)
                dummy += "8";
        xAxisLeft = getTextWidth(f, dummy).width();

        // determine center of date string
        final int dateWidth = getTextWidth(f, "8888/88/88").width();
        xTicks = (width - xAxisLeft) / dateWidth;
      
        try {
			double dataMin = 99999999999.9;
			double dataMax = -99999999999.9;
			double tMin = 99999999999.9;
			double tMax = -99999999999.9;
			
			// retrieve
			JSONTokener jt = new JSONTokener(jsonData);
			JSONArray dataArray = (JSONArray)jt.nextValue();
			int n = dataArray.length();
			double [][] data = new double[n][2];
			for(int index=0; index<n; index++) {
				JSONObject object = (JSONObject) dataArray.get(index);
				
				String time = object.getString("time");
				String value = object.getString("value");

				data[index][0] = Double.valueOf(time);
				data[index][1] = Double.valueOf(value);
				
				if (data[index][0] < tMin)
					tMin = data[index][0];
				if (data[index][0] > tMax)
					tMax = data[index][0];
				
				if (data[index][1] < dataMin)
					dataMin = data[index][1];
				if (data[index][1] > dataMax)
					dataMax = data[index][1];
			}
	        double scaleX = (double)(xAxisRight - xAxisLeft) / (double)(tMax - tMin);
	        double scaleY = (double)(yAxisBottom - yAxisTop) / (dataMax - dataMin);
	        double scaleT = (double)(tMax - tMin) / (double)xTicks;
			
			canvas.drawColor(Color.WHITE);

	        if (header != null) {
	        	int textWidth = getTextWidth(f, header).width();
	        	int plotX = (width / 2) - (textWidth / 2);
	            canvas.drawText(header, plotX, 9, f);
	        }

			Paint black = new Paint();
			black.setColor(Color.BLACK);
			canvas.drawLine(xAxisLeft, yAxisTop, xAxisLeft, yAxisBottom, black);
			canvas.drawLine(xAxisLeft, yAxisBottom, xAxisRight, yAxisBottom, black);

	        // draw ticks vertical
			Paint gray = new Paint();
			gray.setColor(Color.GRAY);
			Paint grayDotted = new Paint();
			grayDotted.set(gray);
			grayDotted.setPathEffect(new DashPathEffect(new float[] { 1, 1 }, 0));
	        for(int yti=0; yti<=yTicks; yti++) {
	                int y = ((yAxisBottom - yAxisTop) * yti) / yTicks + yAxisTop;
	                canvas.drawLine(xAxisLeft - 2, y, xAxisLeft, y, black);
	                double value = (((dataMax - dataMin) / (double)yTicks) * (double)(yTicks - yti) + dataMin);
	                String str = "" + value;
	                if (str.length() > yAxisMaxStrLen)
	                        str = str.substring(0, yAxisMaxStrLen);

	                if (yti < yTicks)
	                	canvas.drawLine(xAxisLeft + 1, y, xAxisRight, y, grayDotted);

	                canvas.drawText(str, 1, y == yAxisTop ? y + 6 : y + 3, f);
	        }

	        // draw ticks horizonal
	        for(int xti=0; xti<=xTicks; xti++) {
	                int x = ((xAxisRight - xAxisLeft) * xti) / xTicks + xAxisLeft;
	                canvas.drawLine(x, yAxisBottom, x, yAxisBottom + 2, black);
	                double value = tMin + scaleT * (double)xti;

	                long epoch = (long)(value * 1000);
	                java.util.Date when = new java.util.Date(epoch);
	                SimpleDateFormat dateFormatterDate = new SimpleDateFormat("dd/MM/yy");
	                SimpleDateFormat dateFormatterTime = new SimpleDateFormat("HH:mm:ss");
	                String strDate = dateFormatterDate.format(when.getTime());
	                String strTime = dateFormatterTime.format(when.getTime());

	                if (xti > 0)
	                	canvas.drawLine(x, yAxisTop + 1, x, yAxisBottom, grayDotted);

	                int xPos;
	                if (xti == 0)
	                        xPos = Math.max(0, x - dateWidth / 2);
	                else if (xti == xTicks)
	                        xPos = width - (dateWidth * 3) / 4;
	                else if (xti == xTicks - 1)
	                        xPos = x - (dateWidth * 5) / 8;
	                else
	                        xPos = x - dateWidth / 2;
	                canvas.drawText(strTime, xPos, yAxisBottom + 14, f);
	                canvas.drawText(strDate, xPos, yAxisBottom + 24, f);
	        }

	        Paint red = new Paint();
	        red.setColor(Color.RED);
			red.setAntiAlias(true);
	        boolean first = true;
	        int yPrev = -1, xPrev = -1;
	        for(int index=0; index<n; index++) {
                double t = data[index][0];
                double value = data[index][1];
                int x = xAxisLeft + (int)(scaleX * (t - tMin));
                int y = yAxisBottom - (int)(scaleY * (value - dataMin));
                if (first) {
                        xPrev = x;
                        yPrev = y;
                        first = false;
                }
                else {
                        canvas.drawLine(xPrev, yPrev, x, y, red);
                        xPrev = x;
                        yPrev = y;
                }
	        }
		}
		catch(Exception e) {
			System.out.println("Graph exception: " + e);
			e.printStackTrace();
			canvas.drawColor(Color.RED);
			canvas.drawText("" + e, 0, height / 2, f);
			int q = url.indexOf("?");
			if (q == -1)
				q = 0;
			canvas.drawText("" + url.substring(q), 0, (height  * 3) / 4, f);
		}
	}
}
