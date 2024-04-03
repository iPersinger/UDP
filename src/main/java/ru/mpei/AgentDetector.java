package ru.mpei;


import com.google.gson.Gson;
import jade.core.AID;
import jade.core.Agent;
import lombok.Data;
import lombok.SneakyThrows;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapNativeException;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Data
public class AgentDetector implements AgentDetectorInterface {
    RawUdpSocketServer rawUdpSocketServer;
    jade.core.Agent agent;

    public AgentDetector(Agent agent) {
        this.agent = agent;
    }

    @SneakyThrows
    @Override
    public void startPublishing(AID aid, int port) {
        boolean isGuid = false;
        if (aid.getLocalName().equals(aid.getName())) {
            isGuid = true;
        }
        AIDdata a = new AIDdata(aid.getLocalName(), isGuid);
        Gson gson = new Gson();
        String json = gson.toJson(a);

        byte[] data = PacketCreator.create(json);

        RawUdpSocketClient client = new RawUdpSocketClient();
        client.initialize(port);
        ScheduledExecutorService service = Executors.newScheduledThreadPool(1);
        service.scheduleWithFixedDelay(()->{
                    if (!agent.isAlive()){
                        service.shutdown();
                    }
                    try {
                        client.send(data);
                    } catch (NotOpenException e) {
                        throw new RuntimeException(e);
                    } catch (PcapNativeException e) {
                        throw new RuntimeException(e);
                    }
                },
                1000,1000, TimeUnit.MILLISECONDS);
    }

    @Override
    public void startDiscovering(int port) {
        rawUdpSocketServer = new RawUdpSocketServer();
        try {
            rawUdpSocketServer.start(port);
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        } catch (NotOpenException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<AID> getActiveAgents() {
        ScheduledExecutorService executorService = Executors.newSingleThreadScheduledExecutor();
        List<AID> result = new ArrayList<>();
        executorService.scheduleAtFixedRate(() -> {
                    List<AIDDataList> AIDList = rawUdpSocketServer.getAIDList();
                    result.clear();
                    for (AIDDataList aidDataList : AIDList) {
                        result.add(new AID(aidDataList.getName(), aidDataList.isIsguid()));
                    }
                    System.out.println(result);
                },
                1000,1000, TimeUnit.MILLISECONDS);

        return result;
    }
}
