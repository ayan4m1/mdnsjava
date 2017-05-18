package net.posick.mDNS.net;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Options;

public class DatagramProcessor extends NetworkProcessor {
  private static final Logger LOG = LoggerFactory.getLogger(DatagramProcessor.class);

  // The default UDP datagram payload size
  private int maxPayloadSize = 512;
  private boolean isMulticast = false;
  private boolean loopbackModeDisabled = false;
  private boolean reuseAddress = true;
  private int ttl = 255;
  private DatagramSocket socket;
  private long lastPacket;

  public DatagramProcessor(final InetAddress ifaceAddress, final InetAddress address,
      final int port, final PacketListener listener) throws IOException {
    super(ifaceAddress, address, port, listener);

    if (address != null) {
      isMulticast = address.isMulticastAddress();
    }

    NetworkInterface netIface = null;
    if (isMulticast) {
      MulticastSocket socket = new MulticastSocket(port);

      // Set the IP TTL to 255, per the mDNS specification [RFC 6762].
      String temp;
      if ((temp = Options.value("mdns_multicast_loopback")) != null && temp.length() > 0) {
        loopbackModeDisabled = "true".equalsIgnoreCase(temp) || "t".equalsIgnoreCase(temp) || "yes"
            .equalsIgnoreCase(temp) || "y".equalsIgnoreCase(temp);
      }

      int tempTtl = Options.intValue("mdns_socket_ttl");
      ttl = tempTtl < 0 ? ttl : tempTtl;

      reuseAddress = true;

      socket.setLoopbackMode(loopbackModeDisabled);
      socket.setReuseAddress(reuseAddress);
      socket.setTimeToLive(ttl);

      socket.setInterface(ifaceAddress);

      socket.joinGroup(address);

      this.socket = socket;
    } else {
      socket = new DatagramSocket(new InetSocketAddress(ifaceAddress, port));
    }

    netIface = NetworkInterface.getByInetAddress(ifaceAddress);

    // Determine maximum mDNS Payload size
    if (netIface == null) {
      netIface = NetworkInterface.getByInetAddress(socket.getLocalAddress());
      if (netIface == null) {
        InetAddress addr = socket.getInetAddress();
        if (addr != null) {
          netIface = NetworkInterface.getByInetAddress(addr);
        }
      }
    }

    if (netIface != null) {
      try {
        mtu = netIface.getMTU();
      } catch (SocketException e) {
        LOG.warn("Error getting MTU from Network Interface {}. Using default MTU.", netIface);
        netIface = null;
      }
    }

    if (netIface == null) {
      List<NetworkInterface> ifaceList = Collections.list(NetworkInterface.getNetworkInterfaces());
      int smallestMtu = DEFAULT_MTU;
      for (NetworkInterface iface : ifaceList) {
        if (!iface.isLoopback() && !iface.isVirtual() && iface.isUp()) {
          int mtu = iface.getMTU();
          if (mtu < smallestMtu) {
            smallestMtu = mtu;
          }
        }
      }
      mtu = smallestMtu;
    }

    maxPayloadSize = mtu - 40 /* IPv6 Header Size */ - 8 /* UDP Header */;
  }

  @Override
  public void close() throws IOException {
    super.close();

    if (isMulticast) {
      try {
        ((MulticastSocket) socket).leaveGroup(address);
      } catch (SecurityException e) {
        LOG.warn("A security error occured while leaving Multicast Group '{}'", Arrays.toString(address.getAddress()), e);
      } catch (Exception e) {
        LOG.warn("Error leaving Multicast Group '{}'", Arrays.toString(address.getAddress()), e);
      }
    }

    socket.close();
  }

  public boolean isLoopbackModeDisabled() {
    return loopbackModeDisabled;
  }

  public boolean isReuseAddress() {
    return reuseAddress;
  }

  public int getTTL() {
    return ttl;
  }

  public int getMaxPayloadSize() {
    return maxPayloadSize;
  }

  public boolean isMulticast() {
    return isMulticast;
  }

  @Override
  public boolean isOperational() {
    return super.isOperational() && socket.isBound() && !socket.isClosed() && (lastPacket <= (
        System.currentTimeMillis() + 120000));
  }

  public void run() {
    lastPacket = System.currentTimeMillis();
    while (!exit) {
      try {
        byte[] buffer = new byte[mtu];
        final DatagramPacket datagram = new DatagramPacket(buffer, buffer.length);
        socket.receive(datagram);
        lastPacket = System.currentTimeMillis();
        if (datagram.getLength() > 0) {
          Packet packet = new Packet(datagram);
          LOG.trace( "-----> Received packet {} <-----", packet.id);
          packet.timer.start();

          executors.executeNetworkTask(new PacketRunner(listener, packet));
        }
      } catch (SecurityException e) {
        LOG.warn("Security issue receiving data from {}", address, e);
      } catch (Exception e) {
        if (!exit) {
          LOG.trace("Error receiving data from {}", address, e);

        }
      }
    }
  }

  @Override
  public void send(final byte[] data) throws IOException {
    if (exit) {
      return;
    }

    DatagramPacket packet = new DatagramPacket(data, data.length, address, port);

    try {
      if (isMulticast) {
        // Set the IP TTL to 255, per the mDNS specification [RFC 6762].
        ((MulticastSocket) socket).setTimeToLive(255);
      }
      socket.send(packet);
    } catch (IOException e) {
      LOG.trace("Error sending datagram to {}", packet.getSocketAddress(), e);

      if ("no route to host".equalsIgnoreCase(e.getMessage())) {
        close();
      }

      IOException ioe = new IOException(
          "Exception \"" + e.getMessage() + "\" occured while sending datagram to \"" + packet
              .getSocketAddress() + "\".", e);
      ioe.setStackTrace(e.getStackTrace());
      throw ioe;
    }
  }

  @Override
  protected void finalize() throws Throwable {
    close();
    super.finalize();
  }
}
