package main;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.jnetpcap.ByteBufferHandler;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PeeringException;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.tcpip.Tcp;

public class Main {
    final static String dumpPath = "dump/10min_before_attack.pcap";
    static int isTCP = 0;
    static int isSYN = 0;
    static int packetCount = 0;
    static List<Long> synPackets = new ArrayList<Long>();
    
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
            
            @Override
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
                    if(tcpHeader.flags_SYN()) {
                        ++isSYN;
                        synPackets.add(header.timestampInMillis());
                    }                        
                }
                
                packetCount++;                
            }
          };

          pcap.loop(10000, handler, "");
          System.out.println("Total: " + packetCount);
          System.out.println("TCP packets: " + isTCP);
          System.out.println("SYN packets: " + isSYN);
          
          
          
          pcap.close();
    }
    
//    void prepareData(ArrayList<String> labels, ArrayList<>) {
//        synPackets
//    }
    
}
