package main;

import org.jnetpcap.Pcap;

public class Main {

    public static void main(String[] args) {
        String fname = "myfile.pcap";
        StringBuilder errbuf = new StringBuilder();
        

        Pcap pcap = Pcap.openOffline(fname, errbuf);
        if (pcap == null) {
          System.err.printf("Error while opening device for capture: "
            + errbuf.toString());
          return;
        }

    }

}
