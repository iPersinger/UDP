package ru.mpei;


import org.pcap4j.core.*;

import java.util.List;

public class RawUdpSocketClient {
    private PcapHandle pcapHandle;

    //    @SneakyThrows
    public void send(byte[] data) throws NotOpenException, PcapNativeException {
        pcapHandle.sendPacket(data);
    }

    //    @SneakyThrows
    public void initialize(int port) throws PcapNativeException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        PcapNetworkInterface networkInterface = null;
        for (PcapNetworkInterface allDev : allDevs) {
            if (allDev.getName().equals("\\Device\\NPF_Loopback")){
                networkInterface = allDev;
                break;
            }
        }
        pcapHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 50);
    }
}