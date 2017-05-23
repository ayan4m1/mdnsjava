package net.posick.mDNS;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import net.posick.mDNS.Lookup.Domain;
import net.posick.mDNS.ServiceRegistrationException.REASON;
import net.posick.mDNS.utils.ListenerProcessor;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.SRVRecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;
import org.xbill.DNS.Update;

@SuppressWarnings({"unchecked", "rawtypes"})
public class MulticastDNSService extends MulticastDNSLookupBase {
  private static final Logger LOG = LoggerFactory.getLogger(MulticastDNSService.class);

  protected class Register {
    private final ServiceInstance service;

    protected Register(final ServiceInstance service) throws UnknownHostException {
      super();
      this.service = service;
    }

    protected void close() throws IOException {
    }

    /**
     * Registers the Service.
     *
     * @return The Service Instances actually Registered
     */
    protected ServiceInstance register() throws IOException {
      // TODO: Implement Probing and Name Conflict Resolution as per RFC 6762 Section 8.
            /*
             * Steps to Registering a Service.
             * 
             * 1. Query the service name of type ANY. Ex. Test._mdc._tcp.local IN ANY Flags: QM
             * a. Add the Service Record to the Authoritative section.
             * b. Repeat 3 queries with a 250 millisecond delay between each query.
             * 2. Send a standard Query Response containing the service records, Opcode: QUERY, Flags: QR, AA, NO ERROR
             * a. Add TXT record to ANSWER section. TTL: 3600
             * b. Add SRV record to ANSWER section. TTL: 120
             * c. Add DNS-SD Services PTR record to ANSWER section. TTL: 3600 Ex. _services._dns-sd.udp.local. IN PTR _mdc._tcp.local.
             * d. Add PTR record to ANSWER section. Ex. _mdc._tcp.local. IN PTR Test._mdc._tcp.local. TTL: 3600
             * e. Add A record to ADDITIONAL section. TTL: 120 Ex. hostname.local. IN A 192.168.1.83
             * f. Add AAAA record to ADDITIONAL section. TTL: 120 Ex. hostname.local. IN AAAA fe80::255:ff:fe4a:6369
             * g. Add NSEC record to ADDITIONAL section. TTL: 120 Ex. hostname.local. IN NSEC next domain: hostname.local. RRs: A AAAA
             * h. Add NSEC record to ADDITIONAL section. TTL: 3600 Ex. Test._mdc._tcp.local. IN NSEC next domain: Test._mdc._tcp.local. RRs: TXT SRV
             * b. Repeat 3 queries with a 2 second delay between each query response.
             */
      final List replies = new ArrayList();
      Message query = Message.newQuery(Record.newRecord(service.getName(), Type.ANY, DClass.IN));

      if (service.getHost() == null) {
        throw new IOException("Service Records must have a target, aka. Host value set.");
      }

      SRVRecord srvRecord = new SRVRecord(service.getName(), DClass.IN, 3600, 0, 0,
          service.getPort(), service.getHost());
      // TODO: Add support for Unicast answers for first query mDNS.createQuery(DClass.IN + 0x8000, Type.ANY, service.getName());

      int tries = 0;
      while (tries++ < 3) {
        querier.sendAsync(query, new ResolverListener() {
          public void handleException(final Object id, final Exception e) {
            synchronized (replies) {
              replies.add(e);
              replies.notifyAll();
            }
          }


          public void receiveMessage(final Object id, final Message m) {
            synchronized (replies) {
              replies.add(m);
              replies.notifyAll();
            }
          }
        });

        synchronized (replies) {
          try {
            replies.wait(Querier.DEFAULT_RESPONSE_WAIT_TIME);
          } catch (InterruptedException e) {
            // ignore
          }

          if (replies.size() > 0) {
            for (Object o : replies) {
              if (o instanceof Exception) {
                if (o instanceof IOException) {
                  throw (IOException) o;
                } else {
                  Exception e = (Exception) o;
                  IOException ioe = new IOException(e.getMessage());
                  ioe.setStackTrace(e.getStackTrace());
                  throw ioe;
                }
              } else {
                Message message = (Message) o;
                if (message.getRcode() == Rcode.NOERROR || message.getRcode()
                    == Rcode.FORMERR) // FORMERR Added to support non RFC 6763 compliant service names and structures, such as lacking a TXT reccord.
                {
                  List<Record> records = MulticastDNSUtils
                      .extractRecords(message, Section.ANSWER, Section.AUTHORITY,
                          Section.ADDITIONAL);
                  for (Record record : records) {
                    if ((record.getType() == Type.SRV) && (record.getTTL() > 0)) {
                      if (!srvRecord.equals(record)) {
                        // Another Service with this same name was found, so registration must fail.
                        throw new ServiceRegistrationException(
                            REASON.SERVICE_NAME_ALREADY_EXISTS,
                            "A service with name \"" + service.getName() + "\" already exists.");
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      replies.clear();

      ServiceName serviceName = service.getName();
      Name domain = new Name(serviceName.getDomain());
      final Update[] updates = new Update[]{new Update(domain), new Update(domain)};
      Name fullTypeName = new Name(serviceName.getFullType() + "." + domain);
      Name typeName = new Name(serviceName.getType() + "." + domain);
      Name shortSRVName = serviceName.getServiceRRName();

      try {
        List<Record> records = new ArrayList<>();
        List<Record> additionalRecords = new ArrayList<>();

        InetAddress[] addresses = service.getAddresses();

        if (addresses != null) {
          for (int index = 0; index < addresses.length; index++) {
            if (addresses[index] != null) {
              if (addresses[index].getAddress().length == 4) {
                additionalRecords.add(
                    new ARecord(service.getHost(), DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_A_TTL,
                        addresses[index]));
              } else {
                additionalRecords.add(
                    new AAAARecord(service.getHost(), DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_A_TTL,
                        addresses[index]));
              }
            }
          }
        }

        records.add(new PTRRecord(typeName, DClass.IN, Constants.DEFAULT_SRV_TTL, shortSRVName));
        if (!fullTypeName.equals(typeName)) {
          records.add(new PTRRecord(fullTypeName, DClass.IN, Constants.DEFAULT_SRV_TTL, shortSRVName));
        }

        records.add(new SRVRecord(shortSRVName, DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_SRV_TTL, 0, 0,
            service.getPort(), service.getHost()));
        records.add(new TXTRecord(shortSRVName, DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_TXT_TTL,
            Arrays.asList(service.getText())));
        additionalRecords.add(
            new NSECRecord(shortSRVName, DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_RR_WITHOUT_HOST_TTL,
                shortSRVName, new int[]{Type.TXT, Type.SRV}));
        additionalRecords.add(
            new NSECRecord(service.getHost(), DClass.IN + Constants.CACHE_FLUSH, Constants.DEFAULT_RR_WITH_HOST_TTL,
                service.getHost(), new int[]{Type.A, Type.AAAA}));

        for (Record record : records) {
          updates[0].add(record);
        }

        for (Record record : additionalRecords) {
          updates[0].addRecord(record, Section.ADDITIONAL);
        }

        records.clear();
        additionalRecords.clear();

        // Register Service Types in a separate request!
        records.add(new PTRRecord(new Name(Constants.SERVICES_NAME + "." + domain),
            DClass.IN, Constants.DEFAULT_SRV_TTL, typeName));
        if (!fullTypeName.equals(typeName)) {
          records.add(new PTRRecord(new Name(Constants.SERVICES_NAME + "." + domain),
              DClass.IN, Constants.DEFAULT_SRV_TTL, fullTypeName));
        }

        for (Record record : records) {
          updates[1].add(record);
        }

        // Updates are sent at least 2 times, one second apart, as per RFC 6762 Section 8.3
        ResolverListener resolverListener = new ResolverListener() {
          public void handleException(final Object id, final Exception e) {
            synchronized (replies) {
              replies.add(e);
              replies.notifyAll();
            }
          }

          public void receiveMessage(final Object id, final Message m) {
            synchronized (replies) {
              replies.add(m);
              replies.notifyAll();
            }
          }
        };

        tries = 0;
        while (tries++ < 2) {
          querier.sendAsync(updates[0], resolverListener);

          long retry = System.currentTimeMillis() + 1000;
          while (System.currentTimeMillis() < retry) {
            try {
              Thread.sleep(1000);
            } catch (InterruptedException e) {
              // ignore
            }
          }
        }
        querier.sendAsync(updates[1], resolverListener);
      } catch (Exception e) {
        synchronized (replies) {
          replies.add(e);
          replies.notifyAll();
        }
      }

      long endTime = System.currentTimeMillis() + 10000;
      List<ServiceInstance> instances = null;
      while ((instances == null) && (System.currentTimeMillis() < endTime)) {
        if (replies.size() == 0) {
          try {
            synchronized (replies) {
              replies.wait(Querier.DEFAULT_RETRY_INTERVAL);
            }
          } catch (InterruptedException e) {
            // ignore
          }
        }

        Lookup lookup = new Lookup(Collections.singletonList(shortSRVName), Type.ANY);
        try {
          instances = lookup.lookupServices().toCompletableFuture().get(1, TimeUnit.MINUTES);

          if (CollectionUtils.isNotEmpty(instances)) {
            LOG.trace("Register - Response received.");

            if (instances.size() > 1) {
              LOG.warn("Register - Warning: More than one service with the name {} was registered.",
                  shortSRVName);
              throw new IOException("Too many services returned! + Instances: " + instances);
            }

            return instances.get(0);
          }
        } catch (Exception e) {
          LOG.error("Error...", e);
        } finally {
          IOUtils.closeQuietly(lookup);
        }
      }

      LOG.error("Register - How did the execution path getting here!?");
      throw new ServiceRegistrationException(ServiceRegistrationException.REASON.UNKNOWN);
    }
  }

  /**
   * The Browse Operation manages individual browse sessions. Retrying broadcasts.
   * Refer to the mDNS specification [RFC 6762]
   *
   * @author Steve Posick
   */
  protected class ServiceDiscoveryOperation implements ResolverListener, Closeable {
    private final Browse browser;
    private final ListenerProcessor<DNSSDListener> listenerProcessor = new ListenerProcessor<>(DNSSDListener.class);
    private final Map<Name, ServiceInstance> services = new LinkedHashMap<>();

    ServiceDiscoveryOperation(final Browse browser) {
      this(browser, null);
    }

    ServiceDiscoveryOperation(final Browse browser, final DNSSDListener listener) {
      this.browser = browser;

      if (listener != null) {
        registerListener(listener);
      }
    }

    public void close() {
      IOUtils.closeQuietly(listenerProcessor);
      IOUtils.closeQuietly(browser);
    }

    public void handleException(final Object id, final Exception e) {
      listenerProcessor.getDispatcher().handleException(id, e);
    }

    public void receiveMessage(final Object id, final Message message) {
      if (message == null) {
        return;
      }

      // Strip the records that are not related to the query.
      Set<Name> additionalNames = new LinkedHashSet<>();
      List<Record> ignoredRecords = new LinkedList<>();
      List<Record> filteredRecords = new LinkedList<>();
      List<Record> thatAnswers = MulticastDNSUtils
          .extractRecords(message, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL);
      for (Record record : thatAnswers) {
        if (answersQuery(record)) {
          Name additionalName = record.getAdditionalName();
          if (additionalName != null) {
            additionalNames.add(additionalName);
          }

          switch (record.getType()) {
            case Type.PTR:
              PTRRecord ptr = (PTRRecord) record;
              additionalNames.add(ptr.getTarget());
              break;
            case Type.SRV:
              SRVRecord srv = (SRVRecord) record;
              additionalNames.add(srv.getTarget());
              break;
            default:
              // ignore
              break;
          }
          filteredRecords.add(record);
        } else {
          ignoredRecords.add(record);
        }
      }

      for (Record record : ignoredRecords) {
        if (additionalNames.contains(record.getName())) {
          filteredRecords.add(record);
        }
      }

      if (filteredRecords.size() > 0) {
        listenerProcessor.getDispatcher().receiveMessage(id, message);

        Map<Name, ServiceInstance> foundServices = new HashMap<>();
        Map<Name, ServiceInstance> removedServices = new HashMap<>();

        for (Record record : filteredRecords) {
          try {
            ServiceInstance service = null;

            switch (record.getType()) {
              case Type.PTR:
                PTRRecord ptr = (PTRRecord) record;

                if (ptr.getTTL() > 0) {
                  ServiceInstance[] instances = extractServiceInstances(querier
                      .send(Message.newQuery(Record.newRecord(ptr.getTarget(), Type.ANY, dclass))));
                  if (ArrayUtils.getLength(instances) > 0) {
                    synchronized (services) {
                      for (int i = 0; i < instances.length; i++) {
                        if (!services.containsKey(instances[i].getName())) {
                          services.put(instances[i].getName(), instances[i]);
                          foundServices.put(instances[i].getName(), instances[i]);
                        }
                      }
                    }
                  }
                } else {
                  synchronized (services) {
                    service = services.get(ptr.getTarget());
                    if (service != null) {
                      services.remove(service.getName());
                      removedServices.put(service.getName(), service);
                    }
                  }
                }
                break;
            }
          } catch (IOException e) {
            LOG.error("Error parsing SRV record", e);

          }
        }
        // TODO: Check found services against already found services!
        for (ServiceInstance service : foundServices.values()) {
          try {
            listenerProcessor.getDispatcher().serviceDiscovered(id, service);
          } catch (Exception e) {
            LOG.error("Error sending serviceDiscovered event", e);
          }
        }

        for (ServiceInstance service : removedServices.values()) {
          try {
            listenerProcessor.getDispatcher().serviceRemoved(id, service);
          } catch (Exception e) {
            LOG.error("Error sending serviceRemoved event", e);
          }
        }
      }
    }

    public void start() {
      browser.start(this);
    }

    boolean answersQuery(final Record record) {
      if (record != null) {
        for (Message query : browser.queries) {
          for (Record question : MulticastDNSUtils.extractRecords(query, Section.QUESTION)) {
            Name questionName = question.getName();
            Name recordName = record.getName();
            int questionType = question.getType();
            int recordType = record.getType();
            int questionDClass = question.getDClass();
            int recordDClass = record.getDClass();

            if (((questionType == Type.ANY) || (questionType == recordType)) && (
                questionName.equals(recordName) || questionName.subdomain(recordName) || recordName
                    .toString().endsWith("." + questionName.toString())) && (
                (questionDClass == DClass.ANY) || ((questionDClass & 0x7FFF) == (recordDClass
                    & 0x7FFF)))) {
              return true;
            }
          }
        }
      }

      return false;
    }


    Browse getBrowser() {
      return browser;
    }

    boolean matchesBrowse(final Message message) {
      if (message != null) {
        List<Record> thatAnswers = MulticastDNSUtils
            .extractRecords(message, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL);
        return thatAnswers.stream().anyMatch(this::answersQuery);
      }

      return false;
    }

    DNSSDListener registerListener(final DNSSDListener listener) {
      return listenerProcessor.registerListener(listener);
    }

    DNSSDListener unregisterListener(final DNSSDListener listener) {
      return listenerProcessor.unregisterListener(listener);
    }
  }

  protected class Unregister {
    private final ServiceName serviceName;

    protected Unregister(final ServiceInstance service) {
      this(service.getName());
    }

    protected Unregister(final ServiceName serviceName) {
      super();
      this.serviceName = serviceName;
    }

    protected void close() throws IOException {
    }

    protected CompletionStage<Boolean> unregister() throws IOException {
    /*
     * Steps to Registering a Service.
     *
     * 1. Send a standard Query Response containing the service records, Opcode: QUERY, Flags: Response, Authoritative, NO ERROR
     * a. Add PTR record to ANSWER section. TTL: 0 Ex. _mdc._tcp.local. IN PTR Test._mdc._tcp.local.
     * b. Repeat 3 queries with a 2 second delay between each query response.
     */
      String domain = serviceName.getDomain();
      Name fullTypeName = new Name(serviceName.getFullType() + "." + domain);
      Name typeName = new Name(serviceName.getType() + "." + domain);
      Name shortSRVName = serviceName.getServiceRRName();

      List<Record> records = new ArrayList<>();
      List<Record> additionalRecords = new ArrayList<>();

      records.add(new PTRRecord(typeName, DClass.IN, 0, shortSRVName));
      if (!fullTypeName.equals(typeName)) {
        records.add(new PTRRecord(fullTypeName, DClass.IN, 0, shortSRVName));
      }

      Update update = new Update(new Name(domain));
      records.forEach(update::add);
      additionalRecords.forEach(record -> update.addRecord(record, Section.ADDITIONAL));

      // Updates are sent at least 2 times, one second apart, as per RFC 6762 Section 8.3
      ResolverListener resolverListener = new ResolverListener() {
        public void handleException(final Object id, final Exception e) {
        }

        public void receiveMessage(final Object id, final Message m) {
        }
      };

      int tries = 0;
      while (tries++ < 3) {
        querier.sendAsync(update, resolverListener);

        long retry = System.currentTimeMillis() + 2000;
        while (System.currentTimeMillis() < retry) {
          try {
            Thread.sleep(2000);
          } catch (InterruptedException e) {
            // ignore
          }
        }
      }

      try (Lookup lookup = new Lookup(Arrays.asList(typeName, fullTypeName), Type.PTR, DClass.ANY)) {
        return lookup.lookupRecords().thenApply(results ->
            results.stream().noneMatch(result -> shortSRVName.equals(((PTRRecord) result).getTarget())));
      }
    }
  }

  protected List<ServiceDiscoveryOperation> discoveryOperations = new ArrayList<>();

  public MulticastDNSService() throws IOException {
    super();
  }

  public void close() throws IOException {
    discoveryOperations.forEach(IOUtils::closeQuietly);
  }

  public CompletionStage<Set<Domain>> getBrowseDomains(final Set<Name> searchPath) {
    Set<Domain> results = new LinkedHashSet<>();
    for (Name name : Constants.ALL_MULTICAST_DNS_DOMAINS) {
      results.add(new Domain(name));
    }

    return getDomains(Arrays.asList(Constants.DEFAULT_BROWSE_DOMAIN_NAME, Constants.BROWSE_DOMAIN_NAME,
        Constants.LEGACY_BROWSE_DOMAIN_NAME), new ArrayList<>(searchPath))
        .thenApply(domains -> {
          results.addAll(domains);
          return results;
        });
  }

  public CompletionStage<Set<Domain>> getDefaultBrowseDomains(final Set<Name> searchPath) {
    Set<Domain> results = new LinkedHashSet<>();
    for (Name name : Constants.ALL_MULTICAST_DNS_DOMAINS) {
      results.add(new Domain(name));
    }
    searchPath.addAll(Constants.ALL_MULTICAST_DNS_DOMAINS);

    return getDomains(Collections.singletonList(Constants.DEFAULT_BROWSE_DOMAIN_NAME),
        new ArrayList<>(searchPath))
        .thenApply(domains -> {
          results.addAll(domains);
          return results;
        });
  }


  public CompletionStage<Set<Domain>> getDefaultRegistrationDomains(final Set<Name> searchPath) {
    Set<Domain> results = new LinkedHashSet<>();
    for (Name name : Constants.ALL_MULTICAST_DNS_DOMAINS) {
      results.add(new Domain(name));
    }
    searchPath.addAll(Constants.ALL_MULTICAST_DNS_DOMAINS);


    return getDomains(Collections.singletonList(Constants.DEFAULT_REGISTRATION_DOMAIN_NAME),
        new ArrayList<>(searchPath))
        .thenApply(domains -> {
          results.addAll(domains);
          return results;
        });
  }


  public CompletionStage<Set<Domain>> getRegistrationDomains(final Set<Name> searchPath) {
    Set<Domain> results = new LinkedHashSet<>();
    for (Name name : Constants.ALL_MULTICAST_DNS_DOMAINS) {
      results.add(new Domain(name));
    }

    return getDomains(Arrays.asList(Constants.DEFAULT_REGISTRATION_DOMAIN_NAME,
        Constants.REGISTRATION_DOMAIN_NAME), new ArrayList<>(searchPath))
        .thenApply(domains -> {
          results.addAll(domains);
          return results;
        });
  }

  public ServiceInstance register(final ServiceInstance service) throws IOException {
    Register register = new Register(service);
    try {
      return register.register();
    } finally {
      register.close();
    }
  }

  /**
   * Starts a Service Discovery Browse Operation and returns an identifier to be used later to stop
   * the Service Discovery Browse Operation.
   *
   * @param browser An instance of a Browse object containing the mDNS/DNS Queries
   * @param listener The DNS Service Discovery Listener to which the events are sent.
   * @return An Object that identifies the Service Discovery Browse Operation.
   */
  public Object startServiceDiscovery(final Browse browser, final DNSSDListener listener)
      throws IOException {
    ServiceDiscoveryOperation discoveryOperation = new ServiceDiscoveryOperation(browser, listener);

    synchronized (discoveryOperations) {
      discoveryOperations.add(discoveryOperation);
    }
    discoveryOperation.start();

    return discoveryOperation;
  }


  /**
   * Stops a Service Discovery Browse Operation.
   *
   * @param id The object identifying the Service Discovery Browse Operation that was returned by
   * "startServiceDiscovery"
   * @return true, if the Service Discovery Browse Operation was successfully stopped, otherwise
   * false.
   */
  public boolean stopServiceDiscovery(final Object id) throws IOException {
    synchronized (discoveryOperations) {
      int pos = discoveryOperations.indexOf(id);
      if (pos >= 0) {
        ServiceDiscoveryOperation discoveryOperation = discoveryOperations.get(pos);
        if (discoveryOperation != null) {
          discoveryOperations.remove(pos);
          discoveryOperation.close();
          return true;
        }
      }
    }

    if (id instanceof ServiceDiscoveryOperation) {
      ((ServiceDiscoveryOperation) id).close();
      return true;
    }

    return false;
  }

  public CompletionStage<Boolean> unregister(final ServiceInstance service) throws IOException {
    Unregister unregister = new Unregister(service);
    try {
      return unregister.unregister();
    } finally {
      unregister.close();
    }
  }

  public CompletionStage<Boolean> unregister(final ServiceName name) throws IOException {
    Unregister unregister = new Unregister(name);
    try {
      return unregister.unregister();
    } finally {
      unregister.close();
    }
  }

  private CompletionStage<Set<Domain>> getDomainsHelper(Set<Domain> currentDomains, List<String> names, final List<Name> newSearchPath) throws IOException {
    Lookup lookup = new Lookup(names.toArray(new String[names.size()]));
    lookup.setSearchPath(newSearchPath);
    lookup.setQuerier(querier);

    CompletionStage<Set<Domain>> domainsFuture = lookup.lookupDomains();
    return domainsFuture.thenCompose(domains -> {
      if (CollectionUtils.isNotEmpty(domains)) {

        List<Name> newDomains = new ArrayList<>();
        for (Domain domain : domains) {
          if (!currentDomains.contains(domain)) {
            newDomains.add(domain.getName());
            currentDomains.add(domain);
          }
        }
        try {
          return getDomainsHelper(currentDomains, names, newDomains);
        } catch (IOException e) {
          return CompletableFuture.completedFuture(currentDomains);
        }
      }
      return CompletableFuture.completedFuture(currentDomains);
    });

  }

  protected CompletionStage<Set<Domain>> getDomains(final List<String> names, final List<Name> path)  {
    Lookup lookup = null;
    try {
      lookup = new Lookup(names.toArray(new String[names.size()]));
      lookup.setSearchPath(path);
      lookup.setQuerier(querier);
      CompletionStage<Set<Domain>> domainsFuture = lookup
          .lookupDomains()
          .thenCompose(domains -> {
            if (CollectionUtils.isNotEmpty(domains)) {

              List<Name> newDomains = domains.stream().map(Domain::getName)
                  .collect(Collectors.toList());
              try {
                return getDomainsHelper(domains, names, newDomains);
              } catch (IOException e) {
                return CompletableFuture.completedFuture(domains);
              }
            }
            return CompletableFuture.completedFuture(domains);
          });

      return domainsFuture;
    } catch (IOException e) {
      LOG.error("Error getting domains", e);
      return CompletableFuture.completedFuture(new HashSet<>());
    } finally {
      IOUtils.closeQuietly(lookup);
    }
  }


  public static boolean hasMulticastDomains(final Message query) {
    List<Record> records = ListUtils.emptyIfNull(MulticastDNSUtils.extractRecords(query, 0, 1, 2, 3));
    return records.stream().anyMatch(record -> isMulticastDomain(record.getName()));
  }


  public static boolean hasUnicastDomains(final Message query) {
    return !hasMulticastDomains(query);
  }


  public static boolean isMulticastDomain(final Name name) {
    boolean ipv4Multicast = Constants.IPv4_MULTICAST_DOMAINS.stream()
        .anyMatch(multicastDomain -> name.equals(multicastDomain) || name.subdomain(multicastDomain));

    boolean ipv6Multicast = Constants.IPv6_MULTICAST_DOMAINS.stream()
        .anyMatch(multicastDomain -> name.equals(multicastDomain) || name.subdomain(multicastDomain));

    return ipv4Multicast || ipv6Multicast;
  }
}
