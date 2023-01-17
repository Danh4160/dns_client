import java.io.*;
import java.net.*;
import java.util.*;


public class DnsClient {

    public static void main(String args[]) throws Exception {

        Set<String> flags = new HashSet<String>();
        flags.add("-t");
        flags.add("-r");
        flags.add("-p");
        flags.add("-mx");
        flags.add("-ns"); 
        
        // Parse arguments first
        // Default values 
        int timeout = 5;       // Optional 
        int maxRetries = 3;    // Optional 
        int portNumber = 53;   // Optional 
        String serverAddress;  // Required
        String domainName;     // Required
        Boolean mxFlag = false;
        Boolean nsFlag = false; 
        String qName;
        String qType = "0x0001";
        String qClass = "0x0001";


        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-t":
                    timeout = Integer.parseInt(args[i+1]);
                    break;
                case "-r":
                    maxRetries = Integer.parseInt(args[i+1]);
                    break;
                case "-p":
                    portNumber = Integer.parseInt(args[i+1]);
                    break;
                case "-mx":
                    if (!nsFlag && !mxFlag) {
                        mxFlag = true;
                        qType = "0x000f";
                    } 
                    break;
                case "-ns":
                    if (!mxFlag && !nsFlag) {
                        nsFlag = true;
                        qType = "0x0002";
                    } 
                    break;
                default:
                    if (args[i].contains("@")) {
                        serverAddress = args[i].replace("@", "");
                        domainName = args[++i];
                    }
            }
        }

        System.out.println(" ")

    }
} 