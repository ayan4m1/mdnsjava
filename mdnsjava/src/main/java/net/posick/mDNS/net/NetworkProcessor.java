package net.posick.mDNS.net;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import net.posick.mDNS.utils.ExecutionTimer;
import net.posick.mDNS.utils.Executors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Options;

public abstract class NetworkProcessor implements Runnable, Closeable {
  private static final Logger LOG = LoggerFactory.getLogger(NetworkProcessor.class);

  protected static class PacketRunner implements Runnable {

    private static long lastPacket = -1;

    PacketListener dispatcher;

    private final Packet[] packets;

    protected PacketRunner(final PacketListener dispatcher, final Packet... packets) {
      this.dispatcher = dispatcher;
      this.packets = packets;
      if (lastPacket <= 0) {
        lastPacket = System.currentTimeMillis();
      }
    }

    public void run() {
      LOG.trace("Running {} on a single thread", packets.length);

      lastPacket = System.currentTimeMillis();

      PacketListener dispatcher = this.dispatcher;
      for (Packet packet : packets) {
        try {
          double took = packet.timer.took(TimeUnit.MILLISECONDS);
          LOG.trace("NetworkProcessor took {} ms to start packet {}.", took, packet.id);
          ExecutionTimer._start();
          LOG.trace("-----> Dispatching packet {} <-----", packet.id);
          dispatcher.packetReceived(packet);
          LOG.trace("Packet {} took {} ms to be dispatched to Listeners.", packet.id, ExecutionTimer._took(TimeUnit.MILLISECONDS));

        } catch (Throwable e) {
          LOG.warn("Error dispatching data packet", e);
        }
      }
    }
  }

  // Normally MTU size is 1500, but can be up to 9000 for jumbo frames.
  public static final int DEFAULT_MTU = 1500;

  public static final int AVERAGE_QUEUE_THRESHOLD = 2;

  public static final int MAX_QUEUE_THRESHOLD = 10;

  public static final int PACKET_MONITOR_NO_PACKET_RECEIVED_TIMEOUT = 100000;

  protected Executors executors = Executors.newInstance();

  protected InetAddress ifaceAddress;

  protected InetAddress address;

  protected boolean ipv6;

  protected int port;

  protected int mtu = DEFAULT_MTU;

  protected transient boolean exit = false;

  protected PacketListener listener;

  protected boolean threadMonitoring = false;

  protected Thread networkReadThread = null;


  public NetworkProcessor(final InetAddress ifaceAddress, final InetAddress address, final int port,
      final PacketListener listener) throws IOException {
    threadMonitoring = Options.check("mdns_network_thread_monitor");

    setInterfaceAddress(ifaceAddress);
    this.address = address;
    setPort(port);

    if (ifaceAddress.getAddress().length != address.getAddress().length) {
      throw new IOException(
          "Interface Address and bind address bust be the same IP specifciation!");
    }

    ipv6 = address.getAddress().length > 4;

    this.listener = listener;
  }

  public void close() throws IOException {
    if (threadMonitoringFuture != null) {
      threadMonitoringFuture.cancel(true);
    }
    exit = true;
  }

  public InetAddress getAddress() {
    return address;
  }

  public InetAddress getInterfaceAddress() {
    return ifaceAddress;
  }

  public int getMTU() {
    return mtu;
  }

  public int getPort() {
    return port;
  }

  public boolean isIPv4() {
    return !ipv6;
  }

  public boolean isIPv6() {
    return ipv6;
  }

  public boolean isOperational() {
    return !exit && executors.isNetworkExecutorOperational();
  }

  public abstract void send(byte[] data) throws IOException;

  public void setInterfaceAddress(final InetAddress address) {
    ifaceAddress = address;
  }

  public void setPort(final int port) {
    this.port = port;
  }

  private ScheduledFuture<?> threadMonitoringFuture;

  public void start() {
    exit = false;
        
        /*
         * This scheduled task monitors the NetworkProcessor, closing it if Packet
         * processing stops or if the Executors it relies upon
         * are shutdown or terminated by any means.
         */
    if (threadMonitoring) {
      threadMonitoringFuture = executors.schedule(new Runnable() {
        public void run() {
          if (!exit) {
            long now = System.currentTimeMillis();
            long lastPacket = PacketRunner.lastPacket;
            boolean operational = isOperational();
            if (now > (lastPacket + PACKET_MONITOR_NO_PACKET_RECEIVED_TIMEOUT)) {
              String msg = "Network Processor has not received a mDNS packet in " + (
                  (double) (now - lastPacket) / (double) 1000) + " seconds";
              if (!executors.isNetworkExecutorOperational()) {
                msg += " - NetworkProcessorExecutor has shutdown!";
              }
              LOG.warn(msg);
            }

            if (!operational) {
              LOG.warn("NetworkProcessor is NOT operational, closing it!");
              try {
                close();
              } catch (IOException e) {
                // ignore
              }
            }
          }
        }
      }, 1, TimeUnit.SECONDS);
    }

    Thread t = new Thread(this);
    t.setName("NetworkProcessor IO Read Thread");
    t.setPriority(Executors.DEFAULT_NETWORK_THREAD_PRIORITY);
    t.setDaemon(true);
    t.start();
    networkReadThread = t;
  }
}
