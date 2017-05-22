package net.posick.mDNS;

import com.google.common.collect.Lists;
import com.spotify.futures.CompletableFutures;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import net.posick.mDNS.utils.ListenerProcessor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Options;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;

/**
 * The MulticastDNSQuerier is a responder that integrates multicast and unicast DNS in accordance to
 * the mDNS specification [RFC 6762]. DNS queries for multicast domains are send as multicast DNS
 * requests, while unicast domain queries are sent as unicast DNS requests.
 *
 * @author posicks
 */
@SuppressWarnings({"rawtypes", "unchecked"})
public class MulticastDNSQuerier implements Querier {
  private static final Logger LOG = LoggerFactory.getLogger(MulticastDNSQuerier.class);

  protected static class Resolution implements ResolverListener {

    private MulticastDNSQuerier querier = null;
    private Message query = null;
    private ResolverListener listener = null;
    private final List<Response> responses = new LinkedList<>();
    private int requestsSent;
    private final List requestIDs = new ArrayList();
    private boolean mdnsVerbose = false;


    Resolution(final MulticastDNSQuerier querier, final Message query,
        final ResolverListener listener) {
      this.querier = querier;
      this.query = query;
      this.listener = listener;
      this.mdnsVerbose = Options.check("mdns_verbose");
    }

    CompletionStage<Message> getResponse() {
      Message response = (Message) query.clone();
      Header header = response.getHeader();

      CompletionStage<List<Message>> messagesCompletionStage = getResults();

      return messagesCompletionStage.thenApply(messages -> {
        boolean found = false;
        if (CollectionUtils.isNotEmpty(messages)) {
          header.setRcode(Rcode.NOERROR);
          header.setOpcode(Opcode.QUERY);
          header.setFlag(Flags.QR);

          for (Message message : messages) {
            Header h = message.getHeader();
            if (h.getRcode() == Rcode.NOERROR) {
              if (h.getFlag(Flags.AA)) {
                header.setFlag(Flags.AA);
              }

              if (h.getFlag(Flags.AD)) {
                header.setFlag(Flags.AD);
              }

              for (int section : new int[]{Section.ANSWER, Section.ADDITIONAL, Section.AUTHORITY}) {
                Record[] records = (Record[]) ArrayUtils.nullToEmpty(message.getSectionArray(section));
                for (Record record : records) {
                  if (!response.findRecord(record)) {
                    response.addRecord(record, section);
                    found = true;
                  }
                }
              }
            }
          }
        }

        if (!found) {
          header.setRcode(Rcode.NXDOMAIN);
        }

        return response;
      });
    }

    CompletionStage<List<Message>> getResults() {
      CompletionStage<List<Response>> responsesCompletionStage = CompletableFutures.poll(() -> CollectionUtils.isEmpty(responses) ? Optional.empty() : Optional.of(responses),
          Duration.ofMillis(10), Executors.newScheduledThreadPool(1));

      return responsesCompletionStage.thenApply(responses -> {
        if (responses.size() > 0) {
          List<Message> messages = responses.stream()
              .filter(response -> !response.inError()).map(Response::getMessage).collect(Collectors.toList());

          List<Exception> exceptions = responses.stream()
              .filter(Response::inError).map(Response::getException).collect(Collectors.toList());

          if (messages.size() > 0) {
            return messages;
          } else if (exceptions.size() > 0) {
            throw new CompletionException(exceptions.get(0));
          }
        }

        return new ArrayList<Message>();
      });
    }

    public void handleException(final Object id, final Exception exception) {
      if ((requestIDs.size() != 0) && (!requestIDs.contains(id) || (this != id) || !equals(id))) {
        LOG.trace("!!!!! Exception Received for ID - {}.", id);
        synchronized (responses) {
          responses.add(new Response(id, exception));
          responses.notifyAll();
        }

        if (listener != null) {
          listener.handleException(this, exception);
        }
      } else if (mdnsVerbose) {
        String msg = "!!!!! Exception Disgarded ";
        if (!((requestIDs.size() != 0) && (!requestIDs.contains(id) || (this != id) || !equals(
            id)))) {
          msg += "[Request ID does not match Response ID - " + id + " ] ";
        }
        LOG.trace(msg, exception);
      }
    }

    public boolean hasResults() {
      return responses.size() >= requestsSent;
    }

    public boolean inError() {
      return responses.stream().allMatch(Response::inError);
    }

    public void receiveMessage(final Object id, final Message message) {
      if ((requestIDs.size() == 0) || requestIDs.contains(id) || (this == id) || equals(id)
          || MulticastDNSUtils.answersAny(query, message)) {
        LOG.trace("!!!! Message Received - " + id + " - " + query.getQuestion());
        synchronized (responses) {
          responses.add(new Response(this, message));
          responses.notifyAll();
        }

        if (listener != null) {
          listener.receiveMessage(this, message);
        }
      } else if (mdnsVerbose) {

        String msg = "!!!!! Message Disgarded ";
        if ((requestIDs.size() != 0) && (!requestIDs.contains(id) || (this != id) || !equals(id))) {
          msg += "[Request ID does not match Response ID] ";
        }
        if (!MulticastDNSUtils.answersAny(query, message)) {
          msg += "[Response does not answer Query]";
        }
        LOG.trace(msg + " - " + message);
      }
    }

    public Object start() {
      requestsSent = 0;
      requestIDs.clear();
      boolean unicast = false;
      boolean multicast = false;
      if (MulticastDNSService.hasUnicastDomains(query) && CollectionUtils.isNotEmpty(querier.unicastResolvers)) {
        for (Resolver resolver : querier.unicastResolvers) {
          unicast = true;
          requestIDs.add(resolver.sendAsync(query, this));
          requestsSent++;
        }
      }

      if (MulticastDNSService.hasMulticastDomains(query) && CollectionUtils.isNotEmpty(querier.multicastResponders)) {
        for (Querier responder : querier.multicastResponders) {
          multicast = true;
          requestIDs.add(responder.sendAsync(query, this));
          requestsSent++;
        }
      }

      if (!unicast && !multicast) {
        LOG.error("Could not execute query, no Unicast Resolvers or Multicast Queriers were available {}", query);
      }
      return this;
    }
  }

  protected static class Response {
    private Object id = null;
    private Message message = null;
    private Exception exception = null;

    protected Response(final Object id, final Exception exception) {
      this.id = id;
      this.exception = exception;
    }

    protected Response(final Object id, final Message message) {
      this.id = id;
      this.message = message;
    }

    public Exception getException() {
      return exception;
    }

    public Object getID() {
      return id;
    }

    public Message getMessage() {
      return message;
    }

    public boolean inError() {
      return exception != null;
    }
  }

  protected ListenerProcessor<ResolverListener> resolverListenerProcessor = new ListenerProcessor<>(
      ResolverListener.class);

  protected ResolverListener resolverListenerDispatcher = resolverListenerProcessor.getDispatcher();

  protected boolean ipv4 = false;

  protected boolean ipv6 = false;

  protected List<Querier> multicastResponders;

  protected List<Resolver> unicastResolvers;

  protected ResolverListener resolverDispatch = new ResolverListener() {
    public void handleException(final Object id, final Exception e) {
      resolverListenerDispatcher.handleException(id, e);
    }

    public void receiveMessage(final Object id, final Message m) {
      resolverListenerDispatcher.receiveMessage(id, m);
    }
  };

  /**
   * Constructs a new IPv4 mDNS Querier using the default Unicast DNS servers for the system.
   */
  public MulticastDNSQuerier() throws IOException {
    this(true, false, Lists.newArrayList(new ExtendedResolver()));
  }

  /**
   * Constructs a new mDNS Querier using the default Unicast DNS servers for the system.
   *
   * @param ipv6 if IPv6 should be enabled.
   */
  public MulticastDNSQuerier(final boolean ipv4, final boolean ipv6) throws IOException {
    this(ipv4, ipv6, new ArrayList<>());
  }


  /**
   * Constructs a new mDNS Querier using the provided Unicast DNS Resolver.
   *
   * @param ipv6 if IPv6 should be enabled.
   * @param unicastResolver The Unicast DNS Resolver
   */
  public MulticastDNSQuerier(final boolean ipv4, final boolean ipv6, final Resolver unicastResolver)
      throws IOException {
    this(ipv4, ipv6, Lists.newArrayList(unicastResolver));
  }


  /**
   * Constructs a new mDNS Querier using the provided Unicast DNS Resolvers.
   *
   * @param ipv6 if IPv6 should be enabled.
   * @param unicastResolvers The Unicast DNS Resolvers
   */
  public MulticastDNSQuerier(final boolean ipv4, final boolean ipv6, final List<Resolver> unicastResolvers)
      throws IOException {
    boolean mdnsVerbose = Options.check("mdns_verbose");

    if (CollectionUtils.isEmpty(unicastResolvers)) {
      this.unicastResolvers = Lists.newArrayList(new ExtendedResolver());
    } else {
      this.unicastResolvers = unicastResolvers;
    }

    Querier ipv4Responder = null;
    Querier ipv6Responder = null;

    IOException ipv4_exception = null;
    IOException ipv6_exception = null;

    if (ipv4) {
      try {
        ipv4Responder = new MulticastDNSMulticastOnlyQuerier(false);
        this.ipv4 = true;
      } catch (IOException e) {
        ipv4Responder = null;
        ipv4_exception = e;
        if (mdnsVerbose) {
          LOG.warn("Error constructing IPv4 mDNS Responder", e);
        }
      }
    }

    if (ipv6) {
      try {
        ipv6Responder = new MulticastDNSMulticastOnlyQuerier(true);
        this.ipv6 = true;
      } catch (IOException e) {
        ipv6Responder = null;
        ipv6_exception = e;
        if (mdnsVerbose) {
          LOG.warn("Error constructing IPv6 mDNS Responder", e);
        }
      }
    }

    if ((ipv4Responder != null) && (ipv6Responder != null)) {
      multicastResponders = Lists.newArrayList(ipv4Responder, ipv6Responder);
      ipv4Responder.registerListener(resolverDispatch);
      ipv6Responder.registerListener(resolverDispatch);
    } else if (ipv4Responder != null) {
      multicastResponders = Lists.newArrayList(ipv4Responder);
      ipv4Responder.registerListener(resolverDispatch);
    } else if (ipv6Responder != null) {
      multicastResponders = Lists.newArrayList(ipv6Responder);
      ipv6Responder.registerListener(resolverDispatch);
    } else {
      if (ipv4_exception != null) {
        throw ipv4_exception;
      } else if (ipv6_exception != null) {
        throw ipv6_exception;
      }
    }
  }


  /**
   * {@inheritDoc}
   */
  public void broadcast(final Message message, final boolean addKnown) throws IOException {
    boolean success = false;
    IOException ex = null;
    for (Querier responder : multicastResponders) {
      try {
        responder.broadcast(message, addKnown);
        success = true;
      } catch (IOException e) {
        ex = e;
      }
    }

    for (Resolver resolver : unicastResolvers) {
      resolver.sendAsync(message, new ResolverListener() {
        public void handleException(final Object id, final Exception e) {
          resolverListenerDispatcher.handleException(id, e);
        }

        public void receiveMessage(final Object id, final Message m) {
          resolverListenerDispatcher.receiveMessage(id, m);
        }
      });
    }

    if (!success && (ex != null)) {
      throw ex;
    }
  }

  public void close() throws IOException {
    multicastResponders.forEach(IOUtils::closeQuietly);
  }

  /**
   * {@inheritDoc}
   */
  public List<Name> getMulticastDomains() {
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


  public List<Resolver> getUnicastResolvers() {
    return unicastResolvers;
  }

  /**
   * {@inheritDoc}
   */
  public boolean isIPv4() {
    return ipv4;
  }


  /**
   * {@inheritDoc}
   */
  public boolean isIPv6() {
    return ipv6;
  }


  /**
   * {@inheritDoc}
   */
  public boolean isOperational() {
    return multicastResponders.stream().allMatch(Querier::isOperational);
  }


  public ResolverListener registerListener(final ResolverListener listener) {
    multicastResponders.forEach(querier -> querier.registerListener(listener));
    return listener;
  }


  public ResolverListener unregisterListener(final ResolverListener listener) {
    multicastResponders.forEach(querier -> querier.unregisterListener(listener));
    return listener;
  }


  /**
   * {@inheritDoc}
   */
  public Message send(final Message query) throws IOException {
    try {
      return sendCompletionStage(query)
          .toCompletableFuture().get(DEFAULT_TIMEOUT, TimeUnit.MILLISECONDS);
    } catch (InterruptedException | ExecutionException e) {
      LOG.error("Unexepcted exception.", e);
      throw new IOException(e);
    } catch (TimeoutException e) {
      LOG.error("Process timeout.", e);
      throw new IOException(e);
    }
  }

  public CompletionStage<Message> sendCompletionStage(final Message query) throws IOException {
    Resolution res = new Resolution(this, query, null);
    res.start();

    return res.getResponse();
  }

  /**
   * {@inheritDoc}
   */
  public Resolution sendAsync(final Message query, final ResolverListener listener) {
    Resolution res = new Resolution(this, query, listener);
    res.start();
    return res;
  }

  /**
   * {@inheritDoc}
   */
  public void setEDNS(final int level) {
    multicastResponders.forEach(querier -> querier.setEDNS(level));
    unicastResolvers.forEach(resolver -> resolver.setEDNS(level));
  }


  /**
   * {@inheritDoc}
   */
  public void setEDNS(final int level, final int payloadSize, final int flags, final List options) {
    multicastResponders.forEach(querier -> querier.setEDNS(level, payloadSize, flags, options));
    unicastResolvers.forEach(resolver -> resolver.setEDNS(level, payloadSize, flags, options));
  }


  /**
   * {@inheritDoc}
   */
  public void setIgnoreTruncation(final boolean flag) {
    multicastResponders.forEach(querier -> querier.setIgnoreTruncation(flag));
    unicastResolvers.forEach(resolver -> resolver.setIgnoreTruncation(flag));
  }

  /**
   * {@inheritDoc}
   */
  public void setPort(final int port) {
    multicastResponders.forEach(querier -> querier.setPort(port));

  }

  /**
   * {@inheritDoc}
   */
  public void setRetryWaitTime(final int secs) {
    multicastResponders.forEach(querier -> querier.setRetryWaitTime(secs));
  }

  /**
   * {@inheritDoc}
   */
  public void setRetryWaitTime(final int secs, final int msecs) {
    multicastResponders.forEach(querier -> querier.setRetryWaitTime(secs, msecs));
  }

  /**
   * {@inheritDoc}
   */
  public void setTCP(final boolean flag) {
    unicastResolvers.forEach(resolver -> resolver.setTCP(flag));
  }

  /**
   * {@inheritDoc}
   */
  public void setTimeout(final int secs) {
    multicastResponders.forEach(querier -> querier.setTimeout(secs));
    unicastResolvers.forEach(resolver -> resolver.setTimeout(secs));
  }

  /**
   * {@inheritDoc}
   */
  public void setTimeout(final int secs, final int msecs) {
    multicastResponders.forEach(querier -> querier.setTimeout(secs, msecs));
    unicastResolvers.forEach(resolver -> resolver.setTimeout(secs, msecs));
  }

  /**
   * {@inheritDoc}
   */
  public void setTSIGKey(final TSIG key) {
    multicastResponders.forEach(querier -> querier.setTSIGKey(key));
    unicastResolvers.forEach(resolver -> resolver.setTSIGKey(key));
  }
}
