package ru.mpei;

public class Agent extends jade.core.Agent {
    protected void setup(){

        AgentDetector agentDetector = new AgentDetector(this);
        agentDetector.startPublishing(getAID(), 1200);
        agentDetector.startDiscovering(1200);
        agentDetector.getActiveAgents();


    }
}
