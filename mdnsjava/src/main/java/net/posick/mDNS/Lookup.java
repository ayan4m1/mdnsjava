package net.posick.mDNS;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import net.posick.mDNS.utils.Wait;
import org.apache.commons.collections4.CollectionUtils;
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

  public Set<Domain> lookupDomains() throws IOException {
    final Set<Domain> domains = Collections.synchronizedSet(new HashSet());
    final List<Exception> exceptions = Collections.synchronizedList(new LinkedList());

    if (CollectionUtils.isNotEmpty(queries)) {
      lookupRecordsAsync(new RecordListener() {
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
                e.printStackTrace(System.err);
              }
            }
          }
        }
      });

      Wait.forResponse(domains);
    }

    for (Name name : searchPath) {
      domains.add(new Domain(name));
    }

    return domains;
  }

  public List<Record> lookupRecords() throws IOException {
    final Queue<Message> messages = new ConcurrentLinkedQueue();
    final Queue<Exception> exceptions = new ConcurrentLinkedQueue();

    lookupRecordsAsync(new ResolverListener() {
      public void handleException(final Object id, final Exception e) {
        exceptions.add(e);
      }

      public void receiveMessage(final Object id, final Message m) {
        messages.add(m);
      }
    });

    Wait.forResponse(messages);

    List<Record> records = new ArrayList();

    for (Message m : messages) {
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
  }

  public void lookupRecordsAsync(final RecordListener listener) throws IOException {
    lookupRecordsAsync(new ResolverListener() {
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

  public void lookupRecordsAsync(final ResolverListener listener) throws IOException {
    for (Message query : queries) {
      getQuerier().sendAsync(query, listener);
    }
  }

  public List<ServiceInstance> lookupServices() throws IOException {
    final List<ServiceInstance> results = new ArrayList();
    results.addAll(Arrays.asList(extractServiceInstances(lookupRecords())));
    return results;
  }

  public static List<Record> lookupRecords(Name name) throws IOException {
    return lookupRecords(Collections.singletonList(name), Type.ANY, DClass.ANY);
  }

  public static List<Record> lookupRecords(List<Name> names) throws IOException {
    return lookupRecords(names, Type.ANY, DClass.ANY);
  }

  public static List<Record> lookupRecords(Name name, int type) throws IOException {
    return lookupRecords(Collections.singletonList(name), type, DClass.ANY);
  }

  public static List<Record> lookupRecords(List<Name> names, int type) throws IOException {
    return lookupRecords(names, type, DClass.ANY);
  }

  public static List<Record> lookupRecords(Name name, int type, int dclass) throws IOException {
    return lookupRecords(Collections.singletonList(name), type, dclass);
  }

  public static List<Record> lookupRecords(List<Name> names, int type, int dclass) throws IOException {
    try (Lookup lookup = new Lookup(names, type, dclass)) {
      return lookup.lookupRecords();
    }
  }

  public static List<ServiceInstance> lookupServices(Name name) throws IOException {
    return lookupServices(Collections.singletonList(name), Type.ANY, DClass.ANY);
  }

  public static List<ServiceInstance> lookupServices(List<Name> names) throws IOException {
    return lookupServices(names, Type.ANY, DClass.ANY);
  }

  public static List<ServiceInstance> lookupServices(Name name, int type) throws IOException {
    return lookupServices(Collections.singletonList(name), type, DClass.ANY);
  }

  public static List<ServiceInstance> lookupServices(List<Name> names, int type) throws IOException {
    return lookupServices(names, type, DClass.ANY);
  }

  public static List<ServiceInstance> lookupServices(Name name, int type, int dclass) throws IOException {
    return lookupServices(Collections.singletonList(name), type, dclass);
  }

  public static List<ServiceInstance> lookupServices(List<Name> names, int type, int dclass) throws IOException {
    try (Lookup lookup = new Lookup(names, type, dclass)) {
      return lookup.lookupServices();
    }
  }
}
