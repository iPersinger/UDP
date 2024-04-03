package ru.mpei;

import jade.core.AID;
import java.util.List;

public interface AgentDetectorInterface {
    void startPublishing(AID aid, int port);
    void startDiscovering(int port);
    List<AID> getActiveAgents();
}
