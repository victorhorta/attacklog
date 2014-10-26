package main;

import static com.googlecode.charts4j.Color.ALICEBLUE;
import static com.googlecode.charts4j.Color.BLACK;
import static com.googlecode.charts4j.Color.BLUEVIOLET;
import static com.googlecode.charts4j.Color.LAVENDER;
import static com.googlecode.charts4j.Color.WHITE;

import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.JFrame;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;

import com.googlecode.charts4j.AxisLabels;
import com.googlecode.charts4j.AxisLabelsFactory;
import com.googlecode.charts4j.AxisStyle;
import com.googlecode.charts4j.AxisTextAlignment;
import com.googlecode.charts4j.BarChart;
import com.googlecode.charts4j.BarChartPlot;
import com.googlecode.charts4j.Data;
import com.googlecode.charts4j.Fills;
import com.googlecode.charts4j.GCharts;
import com.googlecode.charts4j.LinearGradientFill;
import com.googlecode.charts4j.Plots;

public class Main {
    final static String dumpPath = "dump/10min_before_attack.pcap";
    static Date initialTime;
    static Date finalTime;
    static int isTCP = 0;
    static int isSYN = 0;
    static int packetCount = 0;
    static List<Timestamp> synPackets = new ArrayList<Timestamp>();
    static List<Range> chartData = new ArrayList<Range>();
    
    //Ip4 ip = new Ip4();
    //Tcp tcp = new Tcp();
    
    public static void main(String[] args) {
        // filter used:
        // (frame.time >= "Apr  5, 1999 18:54:04.529762000") && (frame.time <= "Apr  5, 1999 19:20:54.269852000")
        
        
        StringBuilder errbuf = new StringBuilder();
        

        Pcap pcap = Pcap.openOffline(dumpPath, errbuf);
        if (pcap == null) {
          System.err.printf("Error while opening device for capture: "
            + errbuf.toString());
          return;
        } else {
            System.out.println("File successfully loaded!");
        }
        // Total packets: 50626
        
        
        ByteBufferHandler<String> handler = new ByteBufferHandler<String>() {
            private final PcapPacket packet = new PcapPacket(JMemory.POINTER);
            
            public void nextPacket(PcapHeader header, ByteBuffer buffer,
                    String user) {
                try {
                    packet.peer(buffer);
                } catch (PeeringException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                } // Peer the data to our packet
                packet.getCaptureHeader().peerTo(header,0); // Now peer the pcap provided header
                packet.scan(Ethernet.ID); // Assuming that first header in packet is ethernet
                
                Tcp tcpHeader = packet.getHeader(new Tcp());

                if(tcpHeader != null) {
                    ++isTCP;
                    if(initialTime == null){
                    	initialTime = new java.sql.Date(header.timestampInMillis());
                    }
                    if(tcpHeader.flags_SYN()) {
                        ++isSYN;
                        synPackets.add(new Timestamp(header.timestampInMillis()));
                     //   System.out.println("" + synPackets.get(synPackets.size() - 1).getDay()
                       // 		+";"+ synPackets.get(synPackets.size() - 1).getMonth()
                        //		+ ";"+ synPackets.get(synPackets.size() - 1).getYear()
                        	//	+ " " + synPackets.get(synPackets.size() - 1).getHours()+
                        	//	 " " + synPackets.get(synPackets.size() - 1).getMinutes()
                        //		+ " " + synPackets.get(synPackets.size() - 1).getSeconds());
                    }   
                    finalTime = new java.sql.Date(header.timestampInMillis());
                }
                
                packetCount++;                
            }
          };

          pcap.loop(-1, handler, "");
          System.out.println("Total: " + packetCount);
          System.out.println("TCP packets: " + isTCP);
          System.out.println("SYN packets: " + isSYN);
          
          System.out.println(initialTime.toLocaleString());
          System.out.println(finalTime.toLocaleString());
          dataProcessing();
          
          drawChart();
          
          pcap.close();
    }
    
//    void prepareData(ArrayList<String> labels, ArrayList<>) {
//        synPackets
//    }
   static void dataProcessing(){
	   if(chartData.isEmpty()){
		   chartData.add(new Range(initialTime));
		   chartData.get(chartData.size()-1).countSyn(synPackets);
	   }
	   while(chartData.get(chartData.size()-1).finalTime.before(finalTime)){
			   chartData.add(new Range(chartData.get(chartData.size()-1).finalTime));
			   chartData.get(chartData.size()-1).countSyn(synPackets);
	   }
   }
    static void drawChart(){
    	 List<Double> db = new ArrayList<Double>();
    	 System.out.println(chartData.size());
    	 for(int i = 0 ; i < chartData.size() ; i++ ){
    		 db.add(((double)chartData.get(i).count / 17));
    		 System.out.println("douvle  " + db.get(db.size() - 1));
    	 }
    	 
    	 BarChartPlot synFlood = Plots.newBarChartPlot(Data.newData(db),BLUEVIOLET,"Syn Package");
    	
    	 BarChart chart = GCharts.newBarChart(synFlood);
    	 
    	 
    	 AxisStyle axisStyle = AxisStyle.newAxisStyle(BLACK, 13, AxisTextAlignment.CENTER);
         AxisLabels pacotes = AxisLabelsFactory.newAxisLabels("Pacotes", 50.0);
         pacotes.setAxisStyle(axisStyle);
         AxisLabels horario = AxisLabelsFactory.newAxisLabels("Horário", 50.0);
         horario.setAxisStyle(axisStyle);
         
         chart.addYAxisLabels(AxisLabelsFactory.newNumericRangeAxisLabels(0, 1600));
         chart.addYAxisLabels(pacotes);
         chart.addXAxisLabels(horario);

         chart.setSize(600, 450);
         chart.setBarWidth(5);
         chart.setSpaceWithinGroupsOfBars(3);
         chart.setDataStacked(true);
         chart.setTitle("Syn Flood - NEPTUNE Interval: " + Range.interval + "s", BLACK, 16);
         chart.setGrid(100, 6.25, 3, 2);
         chart.setBackgroundFill(Fills.newSolidFill(ALICEBLUE));
         LinearGradientFill fill = Fills.newLinearGradientFill(0, LAVENDER, 100);
         fill.addColorAndOffset(WHITE, 0);
         chart.setAreaFill(fill);
         String url = chart.toURLString();
         
         JFrame f = new JFrame("Analisando pacotes");
         
         f.addWindowListener(new WindowAdapter(){
                 public void windowClosing(WindowEvent e) {
                     System.exit(0);
                 }
             });
  
         f.add(new LoadImage(url));
         f.pack();
         f.setVisible(true);
         
         

         // EXAMPLE CODE END. Use this url string in your web or
         // Internet application.
         //Logger.global.info(url);
         //String expectedString = "http://chart.apis.google.com/chart?chf=bg,s,F0F8FF|c,lg,0,E6E6FA,1.0,FFFFFF,0.0&chs=600x450&chd=e:QAbhHrTN,FIWZHCDN,GaMzTNTN&chtt=Team+Scores&chts=000000,16&chg=100.0,10.0,3,2&chxt=y,y,x,x&chxr=0,0.0,100.0|1,0.0,100.0|3,0.0,100.0&chxl=1:|Score|2:|2002|2003|2004|2005|3:|Year&chxp=1,50.0|3,50.0&chxs=1,000000,13,0|3,000000,13,0&chdl=Team+A|Team+B|Team+C&chco=8A2BE2,FF4500,32CD32&chbh=100,20,8&cht=bvs";
         //assertEquals("Junit error", normalize(expectedString), normalize(url));
    }
}
