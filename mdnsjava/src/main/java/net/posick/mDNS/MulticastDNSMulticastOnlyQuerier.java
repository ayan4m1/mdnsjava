package net.posick.mDNS;

import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import net.posick.mDNS.MulticastDNSCache.CacheMonitor;
import net.posick.mDNS.net.DatagramProcessor;
import net.posick.mDNS.net.Packet;
import net.posick.mDNS.net.PacketListener;
import net.posick.mDNS.utils.Executors;
import net.posick.mDNS.utils.ListenerProcessor;
import net.posick.mDNS.utils.Wait;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
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
import org.xbill.DNS.SetResponse;
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

  public class ListenerWrapper implements ResolverListener {
    private final Object id;
    private final Message query;
    private final ResolverListener listener;

    public ListenerWrapper(final Object id, final Message query, final ResolverListener listener) {
      this.id = id;
      this.query = query;
      this.listener = listener;
    }

    @Override
    public boolean equals(final Object o) {
      if ((this == o) || (listener == o)) {
        return true;
      } else if (o instanceof ListenerWrapper) {
        return listener == ((ListenerWrapper) o).listener;
      }

      return false;
    }

    public void handleException(final Object id, final Exception e) {
      if ((this.id == null) || this.id.equals(id)) {
        listener.handleException(this.id, e);
        unregisterListener(this);
      }
    }

    @Override
    public int hashCode() {
      return listener.hashCode();
    }

    public void receiveMessage(final Object id, final Message m) {
      Header h = m.getHeader();
      if (h.getFlag(Flags.QR) || h.getFlag(Flags.AA) || h.getFlag(Flags.AD)) {
        if (MulticastDNSUtils.answersAny(query, m)) {
          listener.receiveMessage(this.id, m);
          unregisterListener(this);
        }
      }
    }
  }

  /**
   * Resolver Listener that replies to queries from the network.
   *
   * @author Steve Posick
   */
  public class MulticastDNSResponder implements ResolverListener {

    public MulticastDNSResponder() throws IOException {
    }

    public void handleException(final Object id, final Exception e) {
    }

    public void receiveMessage(final Object id, final Message message) {
      int rcode = message.getRcode();
      Header header = message.getHeader();
      int opcode = header.getOpcode();

      if (header.getFlag(Flags.QR) || header.getFlag(Flags.AA)) {
        return;
      }

      if (header.getFlag(Flags.TC)) {
        if (ignoreTruncation) {
          LOG.warn("Truncated Message : " + "RCode: " + Rcode.string(rcode) + "; Opcode: " + Opcode
                  .string(opcode) + " - Ignoring subsequent known answer records.");
          return;
        } else {
          // TODO: Implement the reception of truncated packets. (wait 400 to 500 milliseconds for more known answers)
        }
      }

      if (mdnsVerbose) {
        LOG.info("Receive - RCode: " + Rcode.string(rcode));
        LOG.info("Receive - Opcode: " + Opcode.string(opcode));
      }

      try {
        switch (opcode) {
          case Opcode.IQUERY:
          case Opcode.QUERY:
            Message response = cache.queryCache(message, Credibility.AUTH_AUTHORITY);

            if (response != null) {
              Header responseHeader = response.getHeader();
              if ((responseHeader.getCount(Section.ANSWER) > 0) || (
                  responseHeader.getCount(Section.AUTHORITY) > 0) || (
                  responseHeader.getCount(Section.ADDITIONAL) > 0)) {
                if (mdnsVerbose) {
                  LOG.info("Receive - Query Reply ID: " + id + "\n" + response);
                }
                responseHeader.setFlag(Flags.AA);
                responseHeader.setFlag(Flags.QR);
                writeResponse(response);
              } else {
                if (mdnsVerbose) {
                  LOG.info("Receive - No response, client knows answer.");
                }
              }
            }
            break;
          case Opcode.NOTIFY:
          case Opcode.STATUS:
          case Opcode.UPDATE:
            LOG.warn("Receive - Received Invalid Request - Opcode: " + Opcode.string(opcode));
            break;
        }
      } catch (Exception e) {
        LOG.error("Error replying to query", e);
      }
    }
  }


  /**
   * Resolver Listener used cache responses received from the network.
   *
   * @author Steve Posick
   */
  protected class Cacher implements ResolverListener {

    public void handleException(final Object id, final Exception e) {
    }

    public void receiveMessage(final Object id, final Message message) {
      Header header = message.getHeader();
      int rcode = message.getRcode();
      int opcode = header.getOpcode();

      if (ignoreTruncation && header.getFlag(Flags.TC)) {
        LOG.warn("Receive - Truncated Message Ignored : " + "RCode: " + Rcode.string(rcode) + "; Opcode: " + Opcode
                .string(opcode));
        return;
      }

      switch (opcode) {
        case Opcode.IQUERY:
        case Opcode.QUERY:
        case Opcode.NOTIFY:
        case Opcode.STATUS:
          if (header.getFlag(Flags.QR) || header.getFlag(Flags.AA)) {
            updateCache(MulticastDNSUtils
                    .extractRecords(message, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL),
                Credibility.NONAUTH_AUTHORITY);
          } else {
            return;
          }
          break;
        case Opcode.UPDATE:
          // We do not allow updates from the network!
          LOG.error("Updates from the network are not allowed!");
          return;
      }

      if (mdnsVerbose) {
        LOG.info("Receive - RCode: " + Rcode.string(rcode));
        LOG.info("Receive - Opcode: " + Opcode.string(opcode));
      }
    }
  }


  /**
   * The default EDNS payload size
   */
  public static final int DEFAULT_EDNS_PAYLOADSIZE = 1280;

  protected boolean mdnsVerbose = false;

  protected boolean cacheVerbose = false;

  protected ListenerProcessor<ResolverListener> resolverListenerProcessor = new ListenerProcessor<ResolverListener>(
      ResolverListener.class);

  protected ResolverListener resolverListenerDispatcher = resolverListenerProcessor.getDispatcher();

  protected MulticastDNSCache cache;

  protected Cacher cacher;

  protected MulticastDNSResponder responder;

  protected InetAddress multicastAddress;

  protected int port = Constants.DEFAULT_PORT;

  protected OPTRecord queryOPT;

  protected TSIG tsig;

  protected boolean ignoreTruncation = false;

  protected long timeoutValue = DEFAULT_TIMEOUT;

  protected long responseWaitTime = DEFAULT_RESPONSE_WAIT_TIME;

  protected long retryInterval = DEFAULT_RETRY_INTERVAL;

  protected List<DatagramProcessor> multicastProcessors = new ArrayList<DatagramProcessor>();

  protected Executors executors = Executors.newInstance();


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
        if (authRecords.size() > 0) {
          Message m = new Message();
          Header h = m.getHeader();
          h.setOpcode(Opcode.UPDATE);
          for (Record authRecord : authRecords) {
            m.addRecord(authRecord, Section.UPDATE);
          }

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
          for (Record nonauthRecord : nonauthRecords) {
            m.addRecord(nonauthRecord, Section.UPDATE);
          }

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
        for (Record record : records) {
          MulticastDNSUtils.setTLLForRecord(record, 0);
          list.add(record);
        }
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

  public MulticastDNSMulticastOnlyQuerier()
      throws IOException {
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
    executors.scheduleAtFixedRate(new Runnable() {
      public void run() {
        mdnsVerbose = Options.check("mdns_verbose") || Options.check("verbose");
        cacheVerbose = Options.check("mdns_cache_verbose") || Options.check("cache_verbose");
      }
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
      Set<InetAddress> addresses = new HashSet<InetAddress>();
      Set<String> MACs = new HashSet<String>();
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

    cacher = new Cacher();
    registerListener(cacher);

    for (DatagramProcessor multicastProcessor : multicastProcessors) {
      multicastProcessor.start();
    }

    responder = new MulticastDNSResponder();
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
      updateCache(MulticastDNSUtils.extractRecords(message, Section.ZONE, Section.PREREQ,
          Section.UPDATE, Section.ADDITIONAL), Credibility.AUTH_AUTHORITY);
      writeMessageToWire(convertUpdateToQueryResponse(message));
    } else if (addKnownAnswers) {
      Message knownAnswer = cache.queryCache(message, Credibility.ANY);
      for (Integer section : new Integer[]{Section.ANSWER,
          Section.ADDITIONAL,
          Section.AUTHORITY}) {
        Record[] records = knownAnswer.getSectionArray(section);
        if ((records != null) && (records.length > 0)) {
          for (Record record : records) {
            if (!message.findRecord(record)) {
              message.addRecord(record, section);
            }
          }
        }
      }

      writeMessageToWire(message);
    } else {
      writeMessageToWire(message);
    }
  }


  public void close() throws IOException {
    IOUtils.closeQuietly(cache);
    multicastProcessors.forEach(IOUtils::closeQuietly);
    resolverListenerProcessor.close();
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
    boolean ipv4 = isIPv4();
    boolean ipv6 = isIPv6();

    if (ipv4 && ipv6) {
      return Constants.ALL_MULTICAST_DNS_DOMAINS;
    } else if (ipv4) {
      return Constants.IPv4_MULTICAST_DOMAINS;
    } else if (ipv6) {
      return Constants.IPv6_MULTICAST_DOMAINS;
    } else {
      return new ArrayList<>();
    }
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

          Wait.forResponse(results);

          if (exceptions.size() > 0) {
            throw new IOException(exceptions.get(0));
          }
        }
        break;
      case Opcode.UPDATE:
        broadcast(query, false);
        break;
      default:
        throw new IOException(
            "Don't know what to do with Opcode: " + Opcode.string(opcode) + " queries.");
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
    final ListenerWrapper wrapper = new ListenerWrapper(id, query, listener);
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
  public void setCache(final Cache cache) {
    if (cache instanceof MulticastDNSCache) {
      this.cache = (MulticastDNSCache) cache;
      if (this.cache.getCacheMonitor() == null) {
        this.cache.setCacheMonitor(cacheMonitor);
      }
    } else {
      try {
        this.cache = new MulticastDNSCache(cache);
        if (this.cache.getCacheMonitor() == null) {
          this.cache.setCacheMonitor(cacheMonitor);
        }
      } catch (Exception e) {
        if (mdnsVerbose) {
          LOG.error("Error creating multicast dns cache", e);
        }

        throw new IllegalArgumentException("Could not set Cache - " + e.getMessage());
      }
    }
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

  public void setIgnoreTruncation(final boolean ignoreTruncation) {
    this.ignoreTruncation = ignoreTruncation;
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

  protected void applyEDNS(final Message query) {
    if ((queryOPT == null) || (query.getOPT() != null)) {
      return;
    }
    query.addRecord(queryOPT, Section.ADDITIONAL);
  }

  protected Message convertUpdateToQueryResponse(final Message update) {
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

  protected int verifyTSIG(final Message query, final Message response, final byte[] b,
      final TSIG tsig) {
    if (tsig == null) {
      return 0;
    }

    int error = tsig.verify(response, b, query.getTSIG());

    if (mdnsVerbose) {
      LOG.info("TSIG verify: " + Rcode.TSIGstring(error));
    }

    return error;
  }

  private void writeMessageToWire(final Message message) throws IOException {
    Header header = message.getHeader();
    header.setID(0);
    applyEDNS(message);
    if (tsig != null) {
      tsig.apply(message, null);
    }

    byte[] out = message.toWire(Message.MAXLENGTH);
    for (DatagramProcessor multicastProcessor : multicastProcessors) {
      OPTRecord opt = message.getOPT();
      int maxUDPSize = opt == null ?  multicastProcessor.getMaxPayloadSize() : opt.getPayloadSize();

      if (out.length > maxUDPSize) {
        if (header.getFlag(Flags.QR)) {
          throw new IOException("DNS Message too large! - " + out.length + " bytes in size.");
        } else {
          List<Message> messages = MulticastDNSUtils.splitMessage(message);
          for (Message message1 : messages) {
            writeMessageToWire(message1);
          }
          return;
        }
      }

      try {
        multicastProcessor.send(out);
      } catch (Exception e) {
        resolverListenerDispatcher.handleException(message.getHeader().getID(), e);
      }
    }
  }

  /**
   * {@inheritDoc}
   */
  protected void writeResponse(final Message message) throws IOException {
    if (mdnsVerbose) {
      LOG.info("Writing Response to " + multicastAddress.getHostAddress() + ":" + port);
    }
    Header header = message.getHeader();

    header.setFlag(Flags.AA);
    header.setFlag(Flags.QR);
    header.setRcode(0);

    writeMessageToWire(message);
  }

  private void updateCache(final List<Record> records, final int credibility) {
    if (CollectionUtils.isNotEmpty(records)) {
      for (Record record : records) {
        try {
          // Workaround. mDNS Uses high order DClass bit for Unicast Response OK
          Record cacheRecord = MulticastDNSUtils.clone(record);
          MulticastDNSUtils.setDClassForRecord(cacheRecord, cacheRecord.getDClass() & 0x7FFF);
          if (cacheRecord.getTTL() > 0) {
            SetResponse response = cache
                .lookupRecords(cacheRecord.getName(), cacheRecord.getType(), Credibility.ANY);

            List<RRset> rrs = response.answers() == null ? new ArrayList<>() : Arrays.asList(response.answers());
            if (CollectionUtils.isNotEmpty(rrs)) {
              List<Record> cachedRecords = MulticastDNSUtils.extractRecords(rrs);
              if (CollectionUtils.isNotEmpty(cachedRecords)) {
                if (mdnsVerbose) {
                  LOG.info("Updating Cached Record: " + cacheRecord);
                }
                cache.updateRRset(cacheRecord, credibility);
              }
            } else {
              if (mdnsVerbose) {
                LOG.info("Caching Record: " + cacheRecord);
              }
              cache.addRecord(cacheRecord, credibility, null);
            }
          } else {
            // Remove unregistered records from Cache
            cache.removeElementCopy(cacheRecord.getName(), cacheRecord.getType());
          }
        } catch (Exception e) {
          if (mdnsVerbose) {
            LOG.error("Error caching record - " + e.getMessage() + ": " + record, e);
          }
        }
      }
    }
  }
}
