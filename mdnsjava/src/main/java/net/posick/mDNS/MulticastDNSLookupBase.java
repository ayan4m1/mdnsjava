package net.posick.mDNS;

import java.io.Closeable;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import net.posick.mDNS.utils.Misc;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.NameTooLongException;
import org.xbill.DNS.Options;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;

@SuppressWarnings({"unchecked", "rawtypes"})
public abstract class MulticastDNSLookupBase implements Closeable {

  protected static final Logger logger = Misc.getLogger(MulticastDNSLookupBase.class.getName(),
      Options.check("mdns_verbose") || Options.check("verbose"));

  protected static Querier defaultQuerier;

  protected static List<Name> defaultSearchPath;


  protected static final Comparator SERVICE_RECORD_SORTER = (o1, o2) -> {
    if (o1 instanceof Record) {
      if (o2 instanceof Record) {
        final Record thisRecord = (Record) o1;
        final Record thatRecord = (Record) o2;

        final int thisType = thisRecord.getType();
        final int thatType = thatRecord.getType();

        switch (thisType) {
          case Type.SRV:
            return thatType == Type.SRV ? 0 : -1;
          case Type.PTR:
            switch (thatType) {
              case Type.SRV:
                return +1;
              case Type.PTR:
                return 0;
              default:
                return -1;
            }
          case Type.TXT:
            switch (thatType) {
              case Type.PTR:
              case Type.SRV:
                return +1;
              case Type.TXT:
                return 0;
              default:
                return -1;
            }
          case Type.A:
          case Type.AAAA:
            switch (thatType) {
              case Type.PTR:
              case Type.SRV:
              case Type.TXT:
                return +1;
              case Type.A:
              case Type.AAAA:
                return 0;
              default:
                return -1;
            }
          case Type.NSEC:
            switch (thatType) {
              case Type.PTR:
              case Type.SRV:
              case Type.TXT:
              case Type.A:
              case Type.AAAA:
                return +1;
              case Type.NSEC:
                return 0;
              default:
                return -1;
            }
          default:
            return -1;

        }
      }
    }

    return -1;
  };


  protected List<Name> names;

  protected Querier querier;

  protected List<Name> searchPath;

  protected int type = Type.ANY;

  protected Object browseID;

  protected int dclass = DClass.ANY;

  protected List<Message> queries;


  public MulticastDNSLookupBase(final Name... names)
      throws IOException {
    this(Arrays.asList(names), Type.ANY, DClass.ANY);
  }


  public MulticastDNSLookupBase(final List<Name> names, final int type)
      throws IOException {
    this(names, type, DClass.ANY);
  }


  public MulticastDNSLookupBase(final List<Name> names, final int type, final int dclass)
      throws IOException {
    this();

    this.names = names;
    this.type = type;
    this.dclass = dclass;
    buildQueries();
  }


  public MulticastDNSLookupBase(final String... names)
      throws IOException {
    this(names, Type.ANY, DClass.ANY);
  }


  public MulticastDNSLookupBase(final String name, final int type)
      throws IOException {
    this(new String[]{name}, type, DClass.ANY);
  }


  public MulticastDNSLookupBase(final String name, final int type, final int dclass)
      throws IOException {
    this(new String[]{name}, type, dclass);
  }


  public MulticastDNSLookupBase(final String[] names, final int type)
      throws IOException {
    this(names, type, DClass.ANY);
  }


  public MulticastDNSLookupBase(final String[] names, final int type, final int dclass)
      throws IOException {
    this();

    if ((names != null) && (names.length > 0)) {
      List domainNames = new ArrayList();
      for (int index = 0; index < names.length; index++) {
        if (names[index].endsWith(".")) {
          try {
            domainNames.add(new Name(names[index]));
          } catch (TextParseException e) {
            if (logger.isLoggable(Level.FINE)) {
              logger
                  .log(Level.FINE, "Error parsing \"" + names[index] + "\" - " + e.getMessage(), e);
            }
          }
        } else {
          for (Name path : searchPath) {
            try {
              domainNames.add(new Name(names[index] + "." + path));
            } catch (TextParseException e) {
              if (logger.isLoggable(Level.FINE)) {
                logger.log(Level.FINE,
                    "Error parsing \"" + (names[index] + "." + path) + "\" - " + e
                        .getMessage(), e);
              }
            }
          }
        }
      }

      this.names = new ArrayList<>(domainNames);
      this.type = type;
      this.dclass = dclass;
      buildQueries();
    } else {
      throw new UnknownHostException("Invalid Name(s) specified!");
    }
  }


  protected MulticastDNSLookupBase()
      throws IOException {
    super();

    querier = getDefaultQuerier();
    searchPath = getDefaultSearchPath();
  }


  protected MulticastDNSLookupBase(final Message message) throws IOException {
    this();
    queries = Collections.singletonList((Message) message.clone());

    int type = -1;
    int dclass = -1;
    List list = new ArrayList();
    List<Record> records = MulticastDNSUtils.extractRecords(message, Section.QUESTION);
    for (Record r : records) {
      if (!list.contains(r)) {
        list.add(r.getName());
      }

      type = type < 0 ? r.getType() : Type.ANY;
      dclass = dclass < 0 ? r.getDClass() : DClass.ANY;
    }

    if (list.size() > 0) {
      this.type = type;
      this.dclass = dclass;
      names = new ArrayList<>(list);
    }
  }


  /**
   * Adds the name to the list of names to browse
   *
   * @param names Names to add
   */
  public void addNames(final List<Name> names) {
    if ((names != null) && (names.size() > 0)) {
      this.names.addAll(names);
      buildQueries();
    }
  }

  /**
   * Adds a domain to the search path that is used during lookups.
   *
   * @param searchPath Name to add to search path
   */
  public void addSearchPath(final List<Name> searchPath) {
    if ((searchPath != null) && (searchPath.size() > 0)) {
      this.searchPath.addAll(searchPath);
      buildQueries();
    }
  }

  public List<Name> getNames() {
    return names;
  }

  /**
   * Gets the Responder that is being used for this browse operations.
   *
   * @return The responder
   */
  public synchronized Querier getQuerier() {
    return querier;
  }


  public List<Name> getSearchPath() {
    return searchPath;
  }

  /**
   * Sets the names to browse
   *
   * @param names Names to browse
   */
  public void setNames(final List<Name> names) {
    this.names = new ArrayList<>(names);
    buildQueries();
  }

  /**
   * Sets the Responder to be used for this browse operation.
   **/
  public synchronized void setQuerier(final Querier querier) {
    this.querier = querier;
  }


  /**
   * Sets the search path to use when performing this lookup. This overrides
   * the default value.
   *
   * @param domains An array of names containing the search path.
   */
  public void setSearchPath(final List<Name> domains) {
    searchPath = new ArrayList<>(domains);
    buildQueries();
  }

  protected void buildQueries() {
    if ((this.names != null) && (searchPath != null)) {
      List<Name> searchNames = new ArrayList();
      List<Message> newQueries = new ArrayList();
      Message multicastQuery = null;
      for (Name name : this.names) {
        if (name.isAbsolute()) {
          if (MulticastDNSService.isMulticastDomain(name)) {
            if (multicastQuery == null) {
              multicastQuery = Message.newQuery(Record.newRecord(name, type, dclass));
            } else {
              multicastQuery.addRecord(Record.newRecord(name, type, dclass), Section.QUESTION);
            }
          } else {
            newQueries.add(Message.newQuery(Record.newRecord(name, type, dclass)));
          }
          searchNames.add(name);
        } else {
          for (Name aSearchPath : searchPath) {
            Name absoluteName;
            try {
              absoluteName = Name.concatenate(name, aSearchPath);
              if (MulticastDNSService.isMulticastDomain(aSearchPath)) {
                // Use a single Message for Multicast Queries.
                if (multicastQuery == null) {
                  multicastQuery = Message.newQuery(Record.newRecord(absoluteName, type, dclass));
                } else {
                  multicastQuery
                      .addRecord(Record.newRecord(absoluteName, type, dclass), Section.QUESTION);
                }
              } else {
                // Create a Message for each Unicast Query.
                newQueries.add(Message.newQuery(Record.newRecord(absoluteName, type, dclass)));
              }
              searchNames.add(absoluteName);
            } catch (NameTooLongException e) {
              if (logger.isLoggable(Level.FINE)) {
                logger.log(Level.FINE, e.getMessage(), e);
              }
            }
          }
        }
      }

      if (multicastQuery != null) {
        newQueries.add(multicastQuery);
      }
      this.names = new ArrayList<>(searchNames);
      this.queries = new ArrayList<>(newQueries);
    }
  }


  /**
   * Gets the mDNS Querier that will be used as the default by future Lookups.
   *
   * @return The default responder.
   */
  public static synchronized Querier getDefaultQuerier() {
    if (defaultQuerier == null) {
      try {
        defaultQuerier = new MulticastDNSQuerier(true, true);
      } catch (IOException e) {
        logger.log(Level.WARNING, e.getMessage(), e);
      }
    }

    return defaultQuerier;
  }


  /**
   * Gets the search path that will be used as the default by future Lookups.
   *
   * @return The default search path.
   */
  public static List<Name> getDefaultSearchPath() {
    if (defaultSearchPath == null) {
      Name[] configuredSearchPath = ResolverConfig.getCurrentConfig().searchPath();

      int startPos = 0;
      if (configuredSearchPath != null) {
        defaultSearchPath = Arrays.asList(configuredSearchPath);
      } else {
        defaultSearchPath = new ArrayList(defaultQuerier.getMulticastDomains());
      }
    }

    return defaultSearchPath;
  }


  /**
   * Sets the default mDNS Querier to be used as the default by future Lookups.
   **/
  public static synchronized void setDefaultQuerier(final Querier querier) {
    defaultQuerier = querier;
  }


  /**
   * Sets the search path to be used as the default by future Lookups.
   *
   * @param domains The default search path.
   */
//  public static synchronized void setDefaultSearchPath(final List<Name> domains) {
//    defaultSearchPath = domains;
//  }

  /**
   * Sets the search path that will be used as the default by future Lookups.
   *
   * @param domains The default search path.
   * @throws TextParseException A name in the array is not a valid DNS name.
   */
  public static synchronized void setDefaultSearchPath(final List<String> domains)
      throws TextParseException {
    if (domains == null) {
      defaultSearchPath = null;
      return;
    }
    defaultSearchPath = domains.stream().map(domain -> {
      try {
        return Name.fromString(domain, Name.root);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    }).collect(Collectors.toList());
  }


  protected static ServiceInstance[] extractServiceInstances(final Message... messages) {
   List<Record> records = new ArrayList<>();

    for (Message message : messages) {
      List<Record> temp = MulticastDNSUtils
          .extractRecords(message, Section.AUTHORITY, Section.ANSWER, Section.ADDITIONAL);
      records.addAll(temp);
    }

    return extractServiceInstances(records);
  }


  protected static ServiceInstance[] extractServiceInstances(final List<Record> records) {
    Map services = new HashMap();

    ServiceInstance service = null;
    records.sort(SERVICE_RECORD_SORTER);

    for (Record record : records) {
      switch (record.getType()) {
        case Type.SRV:
          try {
            service = new ServiceInstance((SRVRecord) record);
            services.put(service.getName(), service);
          } catch (TextParseException e) {
            logger.log(Level.WARNING,
                "Error processing SRV record \"" + record.getName() + "\" - " + e.getMessage(), e);
          }
          break;
        case Type.PTR:
          PTRRecord ptr = (PTRRecord) record;
          service = (ServiceInstance) services.get(ptr.getTarget());
          if (service != null) {
            if (ptr.getTTL() > 0) {
              service.addPointer(ptr.getName());
            } else {
              service.removePointer(ptr.getName());
            }
          }
          break;
        case Type.TXT:
          TXTRecord txt = (TXTRecord) record;
          service = (ServiceInstance) services.get(txt.getName());
          if (service != null) {
            if (txt.getTTL() > 0) {
              service.addTextRecords(txt);
            } else {
              service.removeTextRecords(txt);
            }
          }
          break;
        case Type.A:
          ARecord a = (ARecord) record;
          for (Object o : services.values()) {
            service = (ServiceInstance) o;
            if (a.getName().equals(service.getHost())) {
              if (a.getTTL() > 0) {
                service.addAddress(a.getAddress());
              } else {
                service.removeAddress(a.getAddress());
              }
            }
          }
          break;
        case Type.AAAA:
          AAAARecord aaaa = (AAAARecord) record;
          for (Object o : services.values()) {
            service = (ServiceInstance) o;
            if (aaaa.getName().equals(service.getHost())) {
              if (aaaa.getTTL() > 0) {
                service.addAddress(aaaa.getAddress());
              } else {
                service.removeAddress(aaaa.getAddress());
              }
            }
          }
          break;
      }
      service = null;
    }

    return (ServiceInstance[]) services.values().toArray(new ServiceInstance[services.size()]);
  }
}
