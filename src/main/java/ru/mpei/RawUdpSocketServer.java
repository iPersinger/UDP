package ru.mpei;


import com.google.gson.Gson;
import com.sun.jna.NativeLibrary;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

@Slf4j
@Data
public class RawUdpSocketServer {
    private long time1;
    private boolean firstTime = false;
    private AIDdata aid;

    private List<AIDDataList> AIDList = new ArrayList<>();


    static {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            NativeLibrary.addSearchPath("wpcap", "C:\\Windows\\System32\\Npcap");
        }
    }
    protected boolean run = true;

    public void start(int port) throws PcapNativeException, NotOpenException {
        run = true;
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        PcapNetworkInterface networkInterface = null;
        for (PcapNetworkInterface allDev : allDevs) {
            if (allDev.getName().equals("\\Device\\NPF_Loopback")){
                networkInterface = allDev;
                break;
            }
        }
        PcapHandle pcapHandle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 100 );
        pcapHandle.setFilter("ip proto \\udp && dst port "+port, BpfProgram.BpfCompileMode.NONOPTIMIZE);
        runInThread(pcapHandle);
    }

    protected void runInThread(PcapHandle pcapHandle) {
        new Thread( ()-> {
            grabPackets(pcapHandle);
        }).start();
    }

    protected void grabPackets(PcapHandle pcapHandle) {


        try {
            pcapHandle.loop(0, (PacketListener) packet -> {

                byte[] rawData = packet.getRawData();
                byte[] data = new byte[rawData.length-32];

                System.arraycopy(rawData, 32, data, 0, data.length);
                String stringDataAgent = new String(data);
                Gson jsonDataAgent = new Gson();
                aid = jsonDataAgent.fromJson(stringDataAgent, AIDdata.class);

                long time1 = System.currentTimeMillis();
                if (aid != null){
                    AIDDataList aidList = new AIDDataList(aid.getName(), aid.isGUID(), time1);
                    boolean found = false;
                    for (int i = 0; i < AIDList.size(); i++) {
                        AIDDataList a = AIDList.get(i);
                        if (a.getName().equals(aidList.getName())) {
                            found = true;
                            if (time1 > a.getTimestamp()) {
                                AIDList.set(i, aidList);
                            }
                            break;
                        }
                    }
                    if (!found) {
                        AIDList.add(aidList);
                    }
                    checkAndUpdateAIDList();
                }

                if (!run){
                    try {
                        pcapHandle.breakLoop();
                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }
                }
            });

        } catch (PcapNativeException | InterruptedException | NotOpenException e) {
            throw new RuntimeException(e);
        }
    }
    private void checkAndUpdateAIDList() {
        long currentTime = System.currentTimeMillis();
        Iterator<AIDDataList> iterator = AIDList.iterator();
        while (iterator.hasNext()) {
            AIDDataList aidList = iterator.next();
            if (currentTime - aidList.getTimestamp() >= 4000) {
                iterator.remove();
            }
        }
    }

}
