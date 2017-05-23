package net.posick.mDNS;

import com.spotify.futures.CompletableFutures;
import java.io.IOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.apache.commons.collections4.CollectionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@SuppressWarnings({"unchecked", "rawtypes"})
public class Lookup extends MulticastDNSLookupBase {

  private static final Logger LOG = LoggerFactory.getLogger(Lookup.class);

  private static final ScheduledExecutorService POLL_EXECUTOR = Executors.newScheduledThreadPool(10);

  public static class Domain {
    private final Name name;
    private final boolean isDefault;
    private final boolean isLegacy;

    protected Domain(final Name name) {
      this.name = name;

      byte[] label = name.getLabel(0);
      isDefault = (char)label[0] == 'd';
      isLegacy = (char)label[0] == 'l';
    }

    public Name getName() {
      return name;
    }

    public boolean isDefault() {
      return isDefault;
    }

    public boolean isLegacy() {
      return isLegacy;
    }

    @Override
    public int hashCode() {
      return name.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
      if (obj == this) {
        return true;
      } else if (name == obj) {
        return true;
      } else if (obj instanceof Domain) {
        return name.equals(((Domain) obj).name);
      }

      return false;
    }

    @Override
    public String toString() {
      return name + (isDefault ? "  [default]" : "") + (isLegacy ? "  [legacy]" : "");
    }
  }

  public interface RecordListener {

    void handleException(Object id, Exception e);

    void receiveRecord(Object id, Record record);
  }

  public Lookup(final Name... names) throws IOException {
    super(names);
  }

  public Lookup(final List<Name> names, final int type) throws IOException {
    super(names, type);
  }

  public Lookup(final Name name, final int type) throws IOException {
    super(Collections.singletonList(name), type);
  }

  public Lookup(final List<Name> names, final int type, final int dclass) throws IOException {
    super(names, type, dclass);
  }

  public Lookup(final Name name, final int type, final int dclass) throws IOException {
    super(Collections.singletonList(name), type, dclass);
  }

  public Lookup(final String... names) throws IOException {
    super(names);
  }

  public Lookup(final String name, final int type) throws IOException {
    super(name, type);
  }

  public Lookup(final String name, final int type, final int dclass) throws IOException {
    super(name, type, dclass);
  }

  public Lookup(final String[] names, final int type) throws IOException {
    super(names, type);
  }

  public Lookup(final String[] names, final int type, final int dclass) throws IOException {
    super(names, type, dclass);
  }

  protected Lookup() throws IOException {
    super();
  }

  protected Lookup(final Message message) throws IOException {
    super(message);
  }

  public void close() throws IOException {
  }

  public CompletionStage<Set<Domain>> lookupDomains() throws IOException {
    final Set<Domain> existingDomains = searchPath.stream().map(Domain::new).collect(Collectors.toSet());

    CompletionStage<Set<Domain>> domainsCompletionStage;

    if (CollectionUtils.isNotEmpty(queries)) {
      final Set<Domain> domains = new HashSet<>();
      final List<Exception> exceptions = new LinkedList<>();

      List<Object> ids = lookupRecordsAsync(new RecordListener() {
        public void handleException(final Object id, final Exception e) {
          exceptions.add(e);
        }

        public void receiveRecord(final Object id, final Record record) {
          if (record.getTTL() > 0) {
            if (record.getType() == Type.PTR) {
              String value = ((PTRRecord) record).getTarget().toString();
              if (!value.endsWith(".")) {
                value += ".";
              }

              // Check if domain is already in the list, add if not, otherwise manipulate booleans.
              try {
                domains.add(new Domain(new Name(value)));
              } catch (TextParseException e) {
                LOG.error("Error parsing domain.", e);
              }
            }
          }
        }
      });

      try {
        Thread.sleep(1000 * 10);
      } catch (Exception e) {

      }

      domainsCompletionStage = CompletableFutures.poll(() -> {
        if (CollectionUtils.isNotEmpty(exceptions)) {
          return Optional.of(domains);
        } else {
          return CollectionUtils.isEmpty(domains) ? Optional.empty() : Optional.of(domains);
        }
      }, Duration.ofMillis(10), POLL_EXECUTOR)
          .exceptionally(throwable -> {
            if (throwable instanceof CancellationException) {
              LOG.warn("Record lookup is timing out at {} milliseconds.", Querier.DEFAULT_RESPONSE_WAIT_TIME);
            } else {
              LOG.error("Unknown error.", throwable);
            }
            return new HashSet<>();
          });

      POLL_EXECUTOR.schedule(() -> domainsCompletionStage.toCompletableFuture().complete(new HashSet<>()),
          Querier.DEFAULT_RESPONSE_WAIT_TIME, TimeUnit.MILLISECONDS);

    } else {
      return CompletableFuture.completedFuture(existingDomains);
    }

    return domainsCompletionStage.thenApply(completedDomains -> {
      completedDomains.addAll(existingDomains);
      return completedDomains;
    });
  }

  public CompletionStage<List<Record>> lookupRecords() throws IOException {
    final List<Message> messages = new ArrayList<>();
    final List<Exception> exceptions = new ArrayList<>();

    List<Object> ids = lookupRecordsAsync(new ResolverListener() {
      public void handleException(final Object id, final Exception e) {
        exceptions.add(e);
      }

      public void receiveMessage(final Object id, final Message m) {
        messages.add(m);
      }
    });


    // TODO (chawley) - Make sure we have a way to timeout without failing.
    CompletionStage<List<Message>> messagesCompletionStage = CompletableFutures
        .poll(() -> CollectionUtils.isEmpty(messages) ? Optional.empty() : Optional.of(messages), Duration.ofMillis(10), POLL_EXECUTOR)
        .exceptionally(throwable -> {
          if (throwable instanceof CancellationException) {
            LOG.warn("Record lookup is timing out at {} milliseconds.", Querier.DEFAULT_RESPONSE_WAIT_TIME);
          } else {
            LOG.error("Unknown error.", throwable);
          }
            return new ArrayList<>();
        });

    POLL_EXECUTOR.schedule(() -> messagesCompletionStage.toCompletableFuture().complete(new ArrayList<>()),
        Querier.DEFAULT_RESPONSE_WAIT_TIME, TimeUnit.MILLISECONDS);

    return messagesCompletionStage.thenApply(messagesCompleted -> {
      List<Record> records = new ArrayList();

      for (Message m : messagesCompleted) {
        switch (m.getRcode()) {
          case Rcode.NOERROR:
            records.addAll(MulticastDNSUtils
                .extractRecords(m, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL));
            break;
          case Rcode.NXDOMAIN:
            break;
        }
      }

      return records;
    });

  }

  public List<Object> lookupRecordsAsync(final RecordListener listener) throws IOException {
    return lookupRecordsAsync(new ResolverListener() {
      public void handleException(final Object id, final Exception e) {
        listener.handleException(id, e);
      }

      public void receiveMessage(final Object id, final Message m) {
        List<Record> records = MulticastDNSUtils
            .extractRecords(m, Section.ANSWER, Section.ADDITIONAL, Section.AUTHORITY);
        for (Record r : records) {
          listener.receiveRecord(id, r);
        }
      }
    });
  }

  public List<Object> lookupRecordsAsync(final ResolverListener listener) throws IOException {
    return queries.stream().map(query -> getQuerier().sendAsync(query, listener))
        .collect(Collectors.toList());
  }

  public CompletionStage<List<ServiceInstance>> lookupServices() throws IOException {
    return lookupRecords().thenApply(records ->  Arrays.asList(extractServiceInstances(records)));
  }

  public static CompletionStage<List<Record>> lookupRecords(Name name) throws IOException {
    return lookupRecords(Collections.singletonList(name), Type.ANY, DClass.ANY);
  }

  public static CompletionStage<List<Record>> lookupRecords(List<Name> names) throws IOException {
    return lookupRecords(names, Type.ANY, DClass.ANY);
  }

  public static CompletionStage<List<Record>> lookupRecords(Name name, int type) throws IOException {
    return lookupRecords(Collections.singletonList(name), type, DClass.ANY);
  }

  public static CompletionStage<List<Record>> lookupRecords(List<Name> names, int type) throws IOException {
    return lookupRecords(names, type, DClass.ANY);
  }

  public static CompletionStage<List<Record>> lookupRecords(Name name, int type, int dclass) throws IOException {
    return lookupRecords(Collections.singletonList(name), type, dclass);
  }

  public static CompletionStage<List<Record>> lookupRecords(List<Name> names, int type, int dclass) throws IOException {
    try (Lookup lookup = new Lookup(names, type, dclass)) {
      return lookup.lookupRecords();
    }
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(Name name) throws IOException {
    return lookupServices(Collections.singletonList(name), Type.ANY, DClass.ANY);
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(List<Name> names) throws IOException {
    return lookupServices(names, Type.ANY, DClass.ANY);
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(Name name, int type) throws IOException {
    return lookupServices(Collections.singletonList(name), type, DClass.ANY);
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(List<Name> names, int type) throws IOException {
    return lookupServices(names, type, DClass.ANY);
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(Name name, int type, int dclass) throws IOException {
    return lookupServices(Collections.singletonList(name), type, dclass);
  }

  public static CompletionStage<List<ServiceInstance>> lookupServices(List<Name> names, int type, int dclass) throws IOException {
    try (Lookup lookup = new Lookup(names, type, dclass)) {
      return lookup.lookupServices();
    }
  }
}
