package net.posick.mDNS;

import java.io.Closeable;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.posick.mDNS.utils.Executors;
import net.posick.mDNS.utils.ListenerProcessor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.IOUtils;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

@SuppressWarnings({"unchecked", "rawtypes"})
public class Browse extends MulticastDNSLookupBase {

  static final Logger logger = Logger.getLogger(Browse.class.getName());

  private final Executors executors = Executors.newInstance();
  protected List<BrowseOperation>browseOperations = new LinkedList<>();

  /**
   * The Browse Operation manages individual browse sessions.  Retrying broadcasts.
   * Refer to the mDNS specification [RFC 6762]
   *
   * @author Steve Posick
   */
  protected class BrowseOperation implements ResolverListener, Runnable, Closeable {
    private int broadcastDelay = 0;

    private ListenerProcessor<ResolverListener> listenerProcessor =
        new ListenerProcessor<>(ResolverListener.class);

    private long lastBroadcast;

    BrowseOperation() {
      this(null);
    }


    BrowseOperation(ResolverListener listener) {
      if (listener != null) {
        registerListener(listener);
      }
    }

    List<Message> getQueries() {
      return queries;
    }

    boolean answersQuery(Record record) {
      if (record != null) {
        for (Message query : queries) {
          for (Record question : MulticastDNSUtils.extractRecords(query, Section.QUESTION)) {
            Name questionName = question.getName();
            Name recordName = record.getName();
            int questionType = question.getType();
            int recordType = record.getType();
            int questionDClass = question.getDClass();
            int recordDClass = record.getDClass();

            if ((questionType == Type.ANY || questionType == recordType) &&
                (questionName.equals(recordName) || questionName.subdomain(recordName) ||
                    recordName.toString().endsWith("." + questionName.toString())) &&
                (questionDClass == DClass.ANY || (questionDClass & 0x7FFF) == (recordDClass
                    & 0x7FFF))) {
              return true;
            }
          }
        }
      }

      return false;
    }

    boolean matchesBrowse(Message message) {
      List<Record> thatAnswers = MulticastDNSUtils
          .extractRecords(message, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL);

      return thatAnswers.stream().anyMatch(this::answersQuery);
    }

    ResolverListener registerListener(ResolverListener listener) {
      return listenerProcessor.registerListener(listener);
    }

    ResolverListener unregisterListener(ResolverListener listener) {
      return listenerProcessor.unregisterListener(listener);
    }

    public void receiveMessage(Object id, Message message) {
      if (message != null) {
        Header header = message.getHeader();

        if (header.getFlag(Flags.QR) || header.getFlag(Flags.AA)) {
          if (matchesBrowse(message)) {
            listenerProcessor.getDispatcher().receiveMessage(id, message);
          }
        }
      }
    }

    public void handleException(Object id, Exception e) {
      listenerProcessor.getDispatcher().handleException(id, e);
    }

    public void run() {
      if (logger.isLoggable(Level.FINE)) {
        long now = System.currentTimeMillis();
        logger.logp(Level.FINE, getClass().getName(), "run",
            "Broadcasting Query for Browse." + (lastBroadcast <= 0 ? ""
                : " Last broadcast was " + ((double) (now - lastBroadcast) / (double) 1000)
                    + " seconds ago."));
        lastBroadcast = System.currentTimeMillis();
      }


      broadcastDelay = broadcastDelay > 0 ? Math.min(broadcastDelay * 2, 3600) : 1;
      executors.schedule(this, broadcastDelay, TimeUnit.SECONDS);

      if (logger.isLoggable(Level.FINE)) {
        logger.logp(Level.FINE, getClass().getName(), "run",
            "Broadcasting Query for Browse Operation.");
      }

      try {
        for (Message query : queries) {
          querier.broadcast((Message) query.clone(), false);
        }
      } catch (Exception e) {
        logger.log(Level.WARNING, "Error broadcasting query for browse - " + e.getMessage(), e);
      }
    }

    public void close() {
      IOUtils.closeQuietly(listenerProcessor);
    }
  }

  protected Browse() throws IOException {
    super();
  }

  public Browse(Name... names) throws IOException {
    super(names);
  }

  public Browse(List<Name> names, int type) throws IOException {
    super(names, type);
  }

  public Browse(List<Name> names, int type, int dclass) throws IOException {
    super(names, type, dclass);
  }

  protected Browse(Message message) throws IOException {
    super(message);
  }

  public Browse(String... names) throws IOException {
    super(names);
  }

  public Browse(String[] names, int type) throws IOException {
    super(names, type);
  }

  public Browse(String[] names, int type, int dclass) throws IOException {
    super(names, type, dclass);
  }

  /**
   * @param listener
   * @throws IOException
   */
  public synchronized void start(ResolverListener listener) {
    if (listener == null) {
      throw new NullPointerException("Error sending asynchronous query, listener is null!");
    }

    if (CollectionUtils.isEmpty(queries)) {
      throw new NullPointerException("Error sending asynchronous query, No queries specified!");
    }

    BrowseOperation browseOperation = new BrowseOperation(listener);
    browseOperations.add(browseOperation);
    querier.registerListener(browseOperation);

    executors.execute(browseOperation);
  }

  public void close() throws IOException {
    browseOperations.forEach(IOUtils::closeQuietly);
  }
}