package net.posick.mDNS;

import com.spotify.futures.CompletableFutures;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import net.posick.mDNS.MulticastDNSCache.CacheMonitor;
import net.posick.mDNS.net.DatagramProcessor;
import net.posick.mDNS.net.Packet;
import net.posick.mDNS.net.PacketListener;
import net.posick.mDNS.resolvers.Cacher;
import net.posick.mDNS.resolvers.ListenerWrapper;
import net.posick.mDNS.resolvers.MulticastDNSResponder;
import net.posick.mDNS.utils.Executors;
import net.posick.mDNS.utils.IpUtil;
import net.posick.mDNS.utils.ListenerProcessor;
import net.posick.mDNS.utils.MessageWriter;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Cache;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Options;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.WireParseException;

/**
 * Implements the Multicast DNS portions of the MulticastDNSQuerier in accordance to RFC 6762.
 *
 * The MulticastDNSMulticastOnlyQuerier is used by the MulticastDNSQuerier to issue multicast DNS
 * requests. Clients should use the MulticastDNSQuerier when issuing DNS/mDNS queries, as
 * Unicast DNS queries will be sent via unicast UDP, and Multicast DNS queries will be sent via
 * multicast UDP.
 *
 * This class may be used if a client wishes to only send requests via multicast UDP.
 *
 * @author Steve Posick
 */
@SuppressWarnings({"unchecked", "rawtypes"})
public class MulticastDNSMulticastOnlyQuerier implements Querier, PacketListener {
  private static final Logger LOG = LoggerFactory.getLogger(MulticastDNSMulticastOnlyQuerier.class);

  // The default EDNS payload size
  public static final int DEFAULT_EDNS_PAYLOADSIZE = 1280;

  private boolean mdnsVerbose = false;
  private boolean cacheVerbose = false;

  private ListenerProcessor<ResolverListener> resolverListenerProcessor = new ListenerProcessor<>(
      ResolverListener.class);

  private ResolverListener resolverListenerDispatcher = resolverListenerProcessor.getDispatcher();
  private MulticastDNSCache cache;
  private InetAddress multicastAddress;
  protected int port = Constants.DEFAULT_PORT;
  private OPTRecord queryOPT;
  private TSIG tsig;
  private boolean ignoreTruncation;
  private long timeoutValue = DEFAULT_TIMEOUT;
  private long responseWaitTime = DEFAULT_RESPONSE_WAIT_TIME;
  private List<DatagramProcessor> multicastProcessors = new ArrayList<>();
  private Executors executors = Executors.newInstance();

  private final CacheMonitor cacheMonitor = new CacheMonitor() {
    private final List<Record> authRecords = new ArrayList<>();
    private final List<Record> nonauthRecords = new ArrayList<>();
    private long lastPoll = System.currentTimeMillis();

    public void begin() {
      if (mdnsVerbose || cacheVerbose) {
        StringBuilder builder = new StringBuilder();
        if (lastPoll > 0) {
          builder.append(
              "Last Poll " + ((double) (System.nanoTime() - lastPoll) / (double) 1000000000)
                  + " seconds ago. ");
        }
        builder.append(" Cache Monitor Check ");
      }
      lastPoll = System.currentTimeMillis();

      authRecords.clear();
      nonauthRecords.clear();
    }


    public void check(final RRset rrs, final int credibility, final int expiresIn) {
      if (mdnsVerbose || cacheVerbose) {
        LOG.info("CacheMonitor check RRset: expires in: " + expiresIn + " seconds : " + rrs);
      }
      long ttl = rrs.getTTL();

      // Update expiry of records in accordance to RFC 6762 Section 5.2
      if (credibility >= Credibility.AUTH_AUTHORITY) {
        if (isAboutToExpire(ttl, expiresIn)) {
          List<Record> records = MulticastDNSUtils.extractRecords(rrs);
          for (Record record : records) {
            try {
              MulticastDNSUtils.setTLLForRecord(record, ttl);
              authRecords.add(record);
            } catch (Exception e) {
              LOG.error("Error adding record", e);
            }
          }
        }
      }
    }


    public void end() {
      try {
        if (CollectionUtils.isNotEmpty(authRecords)) {
          Message m = new Message();
          Header h = m.getHeader();
          h.setOpcode(Opcode.UPDATE);
          authRecords.forEach(authRecord -> m.addRecord(authRecord, Section.UPDATE));

          if (mdnsVerbose || cacheVerbose) {
            LOG.info("CacheMonitor Broadcasting update for Authoritative Records: " + m);
          }
          broadcast(m, false);
        }

        // Notify Local client of expired records
        if (nonauthRecords.size() > 0) {
          Message m = new Message();
          Header h = m.getHeader();
          h.setOpcode(Opcode.QUERY);
          h.setFlag(Flags.QR);
          nonauthRecords.forEach(nonauthRecord -> m.addRecord(nonauthRecord, Section.UPDATE));

          if (mdnsVerbose || cacheVerbose) {
            LOG.info("CacheMonitor Locally Broadcasting Non-Authoritative Records:" + m);
          }
          resolverListenerProcessor.getDispatcher().receiveMessage(h.getID(), m);
        }
      } catch (IOException e) {
        IOException ioe = new IOException(
            "Exception \"" + e.getMessage() + "\" occured while refreshing cached entries.");
        ioe.setStackTrace(e.getStackTrace());
        resolverListenerDispatcher.handleException("", ioe);

        if (mdnsVerbose) {
          LOG.error("Error occurred while refreshing cached entries.", e);
        }
      } catch (Exception e) {
        LOG.error("Unknown error", e);
      }

      authRecords.clear();
      nonauthRecords.clear();
    }


    public void expired(final RRset rrs, final int credibility) {
      if (mdnsVerbose || cacheVerbose) {
        LOG.info("CacheMonitor RRset expired : " + rrs);
      }

      List<Record> list = credibility >= Credibility.AUTH_AUTHORITY ? authRecords : nonauthRecords;
      List<Record> records = MulticastDNSUtils.extractRecords(rrs);

      if (CollectionUtils.isNotEmpty(records)) {
        records.forEach(record -> {
          MulticastDNSUtils.setTLLForRecord(record, 0);
          list.add(record);
        });
      }
    }

    public boolean isOperational() {
      return System.currentTimeMillis() < (lastPoll + 10000);
    }

    protected boolean isAboutToExpire(final long ttl, final int expiresIn) {
      double percentage = (double) expiresIn / (double) ttl;
      return (percentage <= .07f) || ((percentage >= .10f) && (percentage <= .12f)) || (
          (percentage >= .15f) && (percentage <= .17f)) || ((percentage >= .20f) && (percentage
          <= .22f));
    }
  };

  public MulticastDNSMulticastOnlyQuerier() throws IOException {
    this(false);
  }

  public MulticastDNSMulticastOnlyQuerier(final boolean ipv6) throws IOException {
    this(null, InetAddress
        .getByName(ipv6 ? Constants.DEFAULT_IPv6_ADDRESS : Constants.DEFAULT_IPv4_ADDRESS));
  }

  public MulticastDNSMulticastOnlyQuerier(final InetAddress ifaceAddress, final InetAddress address)
      throws IOException {
    super();

    mdnsVerbose = Options.check("mdns_verbose") || Options.check("verbose");
    cacheVerbose = Options.check("mdns_cache_verbose") || Options.check("cache_verbose");
    executors.scheduleAtFixedRate(() -> {
      mdnsVerbose = Options.check("mdns_verbose") || Options.check("verbose");
      cacheVerbose = Options.check("mdns_cache_verbose") || Options.check("cache_verbose");
    }, 1, 1, TimeUnit.MINUTES);

    cache = MulticastDNSCache.DEFAULT_MDNS_CACHE;
    if (cache.getCacheMonitor() == null) {
      cache.setCacheMonitor(cacheMonitor);
    }

    // Set Address to any local address
    setAddress(address);

    // TODO: Re-evaluate this and make sure that The Socket Works properly!
    if (ifaceAddress != null) {
      multicastProcessors.add(new DatagramProcessor(ifaceAddress, address, port, this));
    } else {
      Set<InetAddress> addresses = new HashSet<>();
      Set<String> MACs = new HashSet<>();
      Enumeration<NetworkInterface> netIfaces = NetworkInterface.getNetworkInterfaces();
      while (netIfaces.hasMoreElements()) {
        NetworkInterface netIface = netIfaces.nextElement();

        if (netIface.isUp() && !netIface.isVirtual() && !netIface.isLoopback()) {
          // Generate MAC
          byte[] hwAddr = netIface.getHardwareAddress();
          if (hwAddr != null) {
            StringBuilder builder = new StringBuilder();
            for (byte octet : hwAddr) {
              builder.append(Integer.toHexString((octet & 0x0FF))).append(":");
            }
            if (builder.length() > 1) {
              builder.setLength(builder.length() - 1);
            }
            String mac = builder.toString();

            if (!MACs.contains(mac)) {
              MACs.add(mac);
              Enumeration<InetAddress> ifaceAddrs = netIface.getInetAddresses();
              while (ifaceAddrs.hasMoreElements()) {
                InetAddress addr = ifaceAddrs.nextElement();
                if (address.getAddress().length == addr.getAddress().length) {
                  addresses.add(addr);
                }
              }
            }
          }
        }
      }

      for (InetAddress ifaceAddr : addresses) {
        if (ifaceAddr.getAddress().length == address.getAddress().length) {
          try {
            DatagramProcessor multicastProcessor = new DatagramProcessor(ifaceAddr, address, port,
                this);
            multicastProcessors.add(multicastProcessor);
          } catch (Exception e) {
            LOG.error("Could not bind to address {}", ifaceAddr, e);
          }
        }
      }
    }

    Runtime.getRuntime().addShutdownHook(new Thread(() -> IOUtils.closeQuietly(this), getClass().getSimpleName() + " Shutdown Hook"));

    Cacher cacher = new Cacher(mdnsVerbose, () -> ignoreTruncation, cache);
    registerListener(cacher);

    for (DatagramProcessor multicastProcessor : multicastProcessors) {
      multicastProcessor.start();
    }

    MulticastDNSResponder responder = new MulticastDNSResponder(mdnsVerbose, () -> ignoreTruncation,
        cache, multicastProcessors, resolverListenerDispatcher, tsig, queryOPT);
    registerListener(responder);
  }

  /**
   * {@inheritDoc}
   */
  public void broadcast(final Message message, final boolean addKnownAnswers) throws IOException {
    if (mdnsVerbose) {
      LOG.info("Broadcasting Query to " + multicastAddress.getHostAddress() + ":" + port);
    }

    Header header = message.getHeader();
    boolean isUpdate = header.getOpcode() == Opcode.UPDATE;

    if (isUpdate) {
      cache.updateCache(MulticastDNSUtils.extractRecords(message, Section.ZONE, Section.PREREQ,
          Section.UPDATE, Section.ADDITIONAL), Credibility.AUTH_AUTHORITY);
      MessageWriter.writeMessageToWire(convertUpdateToQueryResponse(message), multicastProcessors, resolverListenerDispatcher, tsig, queryOPT);
    } else if (addKnownAnswers) {
      Message knownAnswer = cache.queryCache(message, Credibility.ANY);
      for (Integer section : new Integer[]{Section.ANSWER, Section.ADDITIONAL, Section.AUTHORITY}) {
        Record[] records = (Record[]) ArrayUtils.nullToEmpty(knownAnswer.getSectionArray(section));
        Stream.of(records).filter(record -> !message.findRecord(record))
            .forEach(record -> message.addRecord(record, section));
      }

      MessageWriter.writeMessageToWire(message, multicastProcessors, resolverListenerDispatcher, tsig, queryOPT);
    } else {
      MessageWriter.writeMessageToWire(message, multicastProcessors, resolverListenerDispatcher, tsig, queryOPT);
    }
  }


  public void close() throws IOException {
    IOUtils.closeQuietly(cache);
    multicastProcessors.forEach(IOUtils::closeQuietly);
    resolverListenerProcessor.close();
  }

  public void setIgnoreTruncation(final boolean ignoreTruncation) {
    this.ignoreTruncation = ignoreTruncation;
  }

  /**
   * {@inheritDoc}
   */
  public Cache getCache() {
    return cache;
  }

  /**
   * {@inheritDoc}
   */
  public List<Name> getMulticastDomains() {
    return IpUtil.getMulticastDomains(isIPv4(), isIPv6());
  }

  /**
   * {@inheritDoc}
   */
  public boolean isIPv4() {
    return multicastProcessors.stream().anyMatch(DatagramProcessor::isIPv4);
  }

  /**
   * {@inheritDoc}
   */
  public boolean isIPv6() {
    return multicastProcessors.stream().anyMatch(DatagramProcessor::isIPv6);
  }

  /**
   * {@inheritDoc}
   */
  public boolean isOperational() {
    for (DatagramProcessor multicastProcessor : multicastProcessors) {
      if (!multicastProcessor.isOperational()) {
        return false;
      }
    }

    return cacheMonitor.isOperational() && executors.isScheduledExecutorOperational() && executors
        .isExecutorOperational();
  }

  public void packetReceived(final Packet packet) {
    if (mdnsVerbose) {
      LOG.info("mDNS Datagram Received!");
    }

    byte[] data = packet.getData();

    // Exclude message sent by this Responder and Message from a non-mDNS port
    if (data.length > 0) {
      // Check that the response is long enough.
      if (data.length < Header.LENGTH) {
        if (mdnsVerbose) {
          LOG.info("Error parsing mDNS Response - Invalid DNS header - too short");
        }
        return;
      }

      try {
        Message message = parseMessage(data);
        resolverListenerDispatcher.receiveMessage(message.getHeader().getID(), message);
      } catch (IOException e) {
        LOG.error("Error parsing mDNS Packet: Packet Data [{}]", Arrays.toString(data), e);
      }
    }
  }

  public ResolverListener registerListener(final ResolverListener listener) {
    return resolverListenerProcessor.registerListener(listener);
  }

  /**
   * {@inheritDoc}
   */
  public Message send(final Message request) throws IOException {
    if (request == null) {
      throw new IOException("Query is null");
    }

    final Message query = (Message) request.clone();
    final int opcode = query.getHeader().getOpcode();

    // If all answers for the query are cached, return immediately. Otherwise,
    // Broadcast the query, waiting minimum response wait time, re-broadcasting the query
    // periodically to ensure that all mDNS Responders on the network have a chance to respond
    // (dropped frames/packets, etc...), and then return the answers received from cache.
    switch (opcode) {
      case Opcode.QUERY:
      case Opcode.IQUERY:
        Message message = cache.queryCache(query, Credibility.ANY);
        if (MulticastDNSUtils.answersAll(query, message)) {
          return message;
        } else {
          final List<Message> results = new ArrayList();
          final List<Exception> exceptions = new ArrayList();

          sendAsync(query, new ResolverListener() {
            public void handleException(final Object id, final Exception e) {
              synchronized (results) {
                exceptions.add(e);
                results.notifyAll();
              }
            }

            public void receiveMessage(final Object id, final Message m) {
              synchronized (results) {
                results.add(m);
                results.notifyAll();
              }
            }
          });

          CompletionStage<List<Message>> resultsCompletionStage = CompletableFutures.poll(
              () -> CollectionUtils.isEmpty(results) ? Optional.empty() : Optional.of(results),
              Duration.ofMillis(10), java.util.concurrent.Executors.newScheduledThreadPool(1));


          try {
            resultsCompletionStage.toCompletableFuture()
                .get(Querier.DEFAULT_RESPONSE_WAIT_TIME, TimeUnit.MILLISECONDS);
          } catch (Exception e) {
            LOG.error("Error completing broadcast.", e);
            throw new IOException(e);
          }

          if (exceptions.size() > 0) {
            throw new IOException(exceptions.get(0));
          }
        }
        break;
      case Opcode.UPDATE:
        broadcast(query, false);
        break;
      default:
        throw new IOException("Don't know what to do with Opcode: " + Opcode.string(opcode) + " queries.");
    }

    return cache.queryCache(query, Credibility.ANY);
  }

  /**
   * {@inheritDoc}
   */
  public Object sendAsync(final Message m, final ResolverListener listener) {
    final Message query = (Message) m.clone();
    final Object id = query.getHeader().getID();
    final int opcode = query.getHeader().getOpcode();
    final ListenerWrapper wrapper = new ListenerWrapper(id, query, listener, resolverListenerProcessor);
    registerListener(wrapper);

    switch (opcode) {
      case Opcode.QUERY:
      case Opcode.IQUERY:
        try {
          final Message message = cache.queryCache(query, Credibility.ANY);
          if ((message != null) && (message.getRcode() == Rcode.NOERROR) && MulticastDNSUtils
              .answersAll(query, message)) {
            executors.execute(() -> listener.receiveMessage(id, message));
          }

          try {
            broadcast(query, false);
          } catch (IOException e) {
            unregisterListener(wrapper);
            listener.handleException(id, e);
          }

          int wait = Options.intValue("mdns_resolve_wait");
          long timeOut =
              System.currentTimeMillis() + (wait > 0 ? wait : Querier.DEFAULT_RESPONSE_WAIT_TIME);
          executors.schedule(() -> unregisterListener(wrapper), timeOut, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
          listener.handleException(id, e);
        }
        break;
      case Opcode.UPDATE:
        try {
          broadcast(query, false);
        } catch (Exception e) {
          listener.handleException(id, e);
          unregisterListener(wrapper);
          break;
        }
        break;
      default:
        listener.handleException(id, new IOException(
            "Don't know what to do with Opcode: " + Opcode.string(opcode) + " queries."));
        unregisterListener(wrapper);
        break;
    }

    return id;
  }

  /**
   * {@inheritDoc}
   */
  public void setAddress(final InetAddress address) {
    multicastAddress = address;
  }

  /**
   * {@inheritDoc}
   */
  public void setEDNS(final int level) {
    setEDNS(level, 0, 0, null);
  }

  /**
   * {@inheritDoc}
   */
  public void setEDNS(final int level, int payloadSize, final int flags, final List options) {
    if ((level != 0) && (level != -1)) {
      throw new IllegalArgumentException("invalid EDNS level - " + "must be 0 or -1");
    }

    if (payloadSize == 0) {
      payloadSize = DEFAULT_EDNS_PAYLOADSIZE;
    }

    queryOPT = new OPTRecord(payloadSize, 0, level, flags, options);
  }

  /**
   * {@inheritDoc}
   */
  public void setPort(final int port) {
    this.port = port;
  }

  /**
   * {@inheritDoc}
   */
  public void setRetryWaitTime(final int secs) {
    setRetryWaitTime(secs, 0);
  }

  /**
   * {@inheritDoc}
   */
  public void setRetryWaitTime(final int secs, final int msecs) {
    responseWaitTime = (secs * 1000L) + msecs;
  }

  /**
   * {@inheritDoc}
   */

  public void setTCP(final boolean flag) {
    // Not implemented. mDNS is UDP only.
  }

  /**
   * {@inheritDoc}
   */
  public void setTimeout(final int secs) {
    setTimeout(secs, 0);
  }

  /**
   * {@inheritDoc}
   */
  public void setTimeout(final int secs, final int msecs) {
    timeoutValue = (secs * 1000L) + msecs;
  }

  /**
   * {@inheritDoc}
   */
  public void setTSIGKey(final TSIG key) {
    tsig = key;
  }

  public ResolverListener unregisterListener(final ResolverListener listener) {
    return resolverListenerProcessor.unregisterListener(listener);
  }

  private Message convertUpdateToQueryResponse(final Message update) {
    Message m = new Message();
    Header h = m.getHeader();

    h.setOpcode(Opcode.QUERY);
    h.setFlag(Flags.AA);
    h.setFlag(Flags.QR);

    Record[] records = update.getSectionArray(Section.UPDATE);
    for (Record record : records) {
      m.addRecord(record, Section.ANSWER);
    }

    records = update.getSectionArray(Section.ADDITIONAL);
    for (Record record : records) {
      m.addRecord(record, Section.ADDITIONAL);
    }

    return m;
  }

  @Override
  protected void finalize() throws Throwable {
    close();
    super.finalize();
  }

  /**
   * Parses a DNS message from a raw DNS packet stored in a byte array.
   *
   * @param b The byte array containing the raw DNS packet
   * @return The DNS message
   * @throws WireParseException If an error occurred while parsing the DNS message
   */
  private Message parseMessage(final byte[] b) throws WireParseException {
    try {
      return new Message(b);
    } catch (IOException e) {
      if (mdnsVerbose) {
        LOG.error("Error creating message.", e);
      }

      WireParseException we;
      if (!(e instanceof WireParseException)) {
        we = new WireParseException("Error parsing message - " + e.getMessage());
        we.setStackTrace(e.getStackTrace());
      } else {
        we = (WireParseException) e;
      }

      throw we;
    }
  }
}
