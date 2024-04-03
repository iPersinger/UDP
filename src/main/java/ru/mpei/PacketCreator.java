package ru.mpei;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import com.sun.jna.NativeLibrary;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.UdpPort;
import org.slf4j.LoggerFactory;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

public  class PacketCreator {
    static {

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            NativeLibrary.addSearchPath("wpcap", "C:\\Windows\\System32\\Npcap");
        }
    }

    public static byte[] create(String data) throws PcapNativeException, UnknownHostException {
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        PcapNetworkInterface networkInterface = null;
        for (PcapNetworkInterface allDev : allDevs) {
            if (allDev.getName().equals("\\Device\\NPF_Loopback")){
                networkInterface = allDev;
                break;
            }
        }

        Logger pcapLogger = (Logger) LoggerFactory.getLogger("org.pcap4j");
        pcapLogger.setLevel(Level.OFF);


        Packet udpPayload = new UnknownPacket.Builder().rawData(data.getBytes()).build();
        byte[] UDPData = udpPayload.getRawData();

        // Создание IP заголовка
        Inet4Address srcIp = (Inet4Address) InetAddress.getByName("10.19.116.19");
        Inet4Address dstIp = (Inet4Address) InetAddress.getByName("10.19.116.19");

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder()
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .srcAddr(srcIp)
                .dstAddr(dstIp)
                .protocol(IpNumber.UDP)
                .correctChecksumAtBuild(true)
                .totalLength((short) (20+UDPData.length))
                .correctLengthAtBuild(true);

        // Создание UDP заголовка

        UdpPort srcPort = UdpPort.getInstance((short) 56878);
        UdpPort dstPort = UdpPort.getInstance((short) 1200);
        UdpPacket.Builder udpBuilder = new UdpPacket.Builder()
                .srcPort(srcPort)
                .dstPort(dstPort)
                .correctChecksumAtBuild(true);

        // Создание данных UDP пакета


        // Сборка пакета
        udpBuilder.payloadBuilder(new UnknownPacket.Builder().rawData(data.getBytes()));
        udpBuilder.length((short) (UDPData.length + 8));

        int sum = 0;

        for (byte b : UDPData) {
            sum += b;
        }
        udpBuilder.checksum((short) sum);
        udpBuilder.srcAddr(srcIp);
        udpBuilder.dstAddr(dstIp);



        ipBuilder.payloadBuilder(udpBuilder);
        IpV4Packet packet = ipBuilder.build();
        byte[] ipBytes = packet.getRawData();
        byte[] ff = new byte[] {2, 0, 0, 0};
        // Создаем новый массив для объединенных данных
        byte[] combinedArray = new byte[ipBytes.length + ff.length];


        System.arraycopy(ff, 0, combinedArray, 0, ff.length);
        System.arraycopy(ipBytes, 0, combinedArray, ff.length, ipBytes.length);

        return combinedArray;
    }
}
