package org.xbill.DNS;

import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.posick.mDNS.utils.Misc;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.collections4.ListUtils;
import org.apache.commons.lang3.StringUtils;

@SuppressWarnings({"rawtypes", "unchecked"})
public class MulticastDNSUtils {

  private static final Logger logger = Misc
      .getLogger(MulticastDNSUtils.class, Options.check("mdns_verbose"));

  /**
   * Tests if the response message answers all of the questions within the query message.
   *
   * @param query The query message
   * @param response The response message
   * @return True if the response message answers all of the questions in the query message.
   */
  public static boolean answersAll(final Message query, final Message response) {
    switch (response.getHeader().getOpcode()) {
      case Opcode.QUERY:
      case Opcode.IQUERY:
      case Opcode.NOTIFY:
      case Opcode.STATUS:
        int index = 0;
        List<Record> qRecords = MulticastDNSUtils.extractRecords(query, Section.QUESTION);
        List<Record> rRecords = MulticastDNSUtils.extractRecords(response, Section.QUESTION);
        boolean[] similarArray = new boolean[qRecords.size()];
        for (Record qRecord : qRecords) {
          similarArray[index] = false;
          for (Record rRecord : rRecords) {
            if (qRecord.getName().equals(rRecord.getName()) &&
                ((rRecord.getType() == Type.ANY) || (qRecord.getType() == rRecord.getType()))) {
              similarArray[index] = true;
              break;
            }
          }
          index++;
        }

        for (boolean similar : similarArray) {
          if (!similar) {
            return false;
          }
        }
        return true;
    }

    return false;
  }


  /**
   * Tests if the response message answers any of the questions within the query message.
   *
   * @param query The query message
   * @param response The response message
   * @return True if the response message answers any of the questions in the query message.
   */
  public static boolean answersAny(final Message query, final Message response) {
    Header h = response.getHeader();

    if (!h.getFlag(Flags.QR)) {
      return false;
    }

    switch (h.getOpcode()) {
      case Opcode.QUERY:
      case Opcode.IQUERY:
      case Opcode.NOTIFY:
      case Opcode.STATUS:
        List<Record> qRecords = MulticastDNSUtils.extractRecords(query, Section.QUESTION);
        List<Record> rRecords = MulticastDNSUtils
            .extractRecords(response, Section.ANSWER, Section.ADDITIONAL, Section.AUTHORITY);
        for (Record qRecord : qRecords) {
          for (Record rRecord : rRecords) {
            if (qRecord.getName().equals(rRecord.getName()) &&
                ((qRecord.getType() == Type.ANY) || (qRecord.getType() == rRecord.getType()))) {
              return true;
            }
          }
        }
    }

    return false;
  }


  public static Record clone(final Record record) {
    return record.cloneRecord();
  }


  public static List<Record> extractRecords(final Message message, final int... sections) {
    List<Record> records = new ArrayList<>();

    for (int section : sections) {
      Record[] tempRecords = message.getSectionArray(section);
      if (tempRecords != null && tempRecords.length > 0) {
        records.addAll(Arrays.asList(tempRecords));
      }
    }

    return records;
  }


  public static final List<Record> extractRecords(final RRset rrset) {
    if (rrset == null) {
      return new ArrayList<>();
    }

    Iterator<Record> iterator = rrset.rrs(false);
    return IteratorUtils.toList(iterator);
  }


  public static final List<Record> extractRecords(final List<RRset> rrs) {
    List<Record> results = new ArrayList<>();

    if (CollectionUtils.isNotEmpty(rrs)) {
      rrs.forEach(rr -> results.addAll(extractRecords(rr)));
    }

    return results;
  }


  public static String getHostName() {
    String hostname = System.getenv().get("HOSTNAME");
    if (StringUtils.isBlank(hostname)) {
      hostname = System.getenv().get("COMPUTERNAME");
    }

    if (StringUtils.isBlank(hostname)) {
      try {
        InetAddress localhost = InetAddress.getLocalHost();
        hostname = localhost.getHostName();

        if ((hostname == null) || hostname.startsWith("unknown")) {
          hostname = localhost.getCanonicalHostName();
        }
      } catch (UnknownHostException e) {
      }
    }

    return hostname;
  }


  public static List<InetAddress> getLocalAddresses() {
    List<InetAddress> addresses = new ArrayList<>();
    try {
      Enumeration<NetworkInterface> enet = NetworkInterface.getNetworkInterfaces();
      while (enet.hasMoreElements()) {
        NetworkInterface net = enet.nextElement();
        if (!net.isLoopback()) {
          addresses.addAll(Collections.list(net.getInetAddresses()));
        }
      }
    } catch (SocketException e) {
      // ignore
    }

    return addresses;
  }


  public static String getMachineName() {
    String name = null;

    try {
      Enumeration<NetworkInterface> enet = NetworkInterface.getNetworkInterfaces();

      while (enet.hasMoreElements() && (name == null)) {
        NetworkInterface net = enet.nextElement();

        if (!net.isLoopback()) {
          Enumeration<InetAddress> eaddr = net.getInetAddresses();

          while (eaddr.hasMoreElements()) {
            InetAddress inet = eaddr.nextElement();

            if (!inet.getCanonicalHostName().equalsIgnoreCase(inet.getHostAddress())) {
              name = inet.getCanonicalHostName();
              break;
            }
          }
        }
      }
    } catch (SocketException e) {
      // ignore
    }

    return name;
  }


  public static Name getTargetFromRecord(final Record record) {
    if (record instanceof SingleNameBase) {
      return ((SingleNameBase) record).getSingleName();
    } else {
      try {
        Method method = record.getClass().getMethod("getTarget");
        if (method != null) {
          Object target = method.invoke(record);
          if (target instanceof Name) {
            return (Name) target;
          }
        }
      } catch (Exception e) {
        logger.logp(Level.FINE, MulticastDNSUtils.class.getName(), "getTargetFromRecord",
            "No target specified in record " + record.getClass().getSimpleName() + ": " + record);
      }
    }

    return null;
  }


  /**
   * Compares the 2 messages and determines if they are equal.
   *
   * @return True if the messages are equal
   */
  public static boolean messagesEqual(final Message message1, final Message message2) {
    if (message1 == message2) {
      return true;
    } else if ((message1 == null) || (message2 == null)) {
      return false;
    } else {
      boolean headerEqual;
      Header responseHeader = message1.getHeader();
      Header queryHeader = message2.getHeader();

      if (responseHeader == queryHeader) {
        headerEqual = false;
      } else if ((responseHeader == null) || (queryHeader == null)) {
        headerEqual = false;
      } else {
        boolean[] responseFlags = responseHeader.getFlags();
        boolean[] queryFlags = queryHeader.getFlags();
        if (!Arrays.equals(responseFlags, queryFlags)) {
          return false;
        }

        headerEqual = (responseHeader.getOpcode() == queryHeader.getOpcode()) &&
            (responseHeader.getRcode() == queryHeader.getRcode());
      }

      return headerEqual && ListUtils
          .isEqualList(MulticastDNSUtils.extractRecords(message2, 0, 1, 2, 3),
              MulticastDNSUtils.extractRecords(message1, 0, 1, 2, 3));
    }
  }


  public static Message newQueryResponse(final List<Record> records, final int section) {
    Message message = new Message();
    Header header = message.getHeader();

    header.setRcode(Rcode.NOERROR);
    header.setOpcode(Opcode.QUERY);
    header.setFlag(Flags.QR);

    records.forEach(record -> message.addRecord(record, section));

    return message;
  }


  public static void setDClassForRecord(final Record record, final int dclass) {
    record.dclass = dclass;
  }

  public static void setTLLForRecord(final Record record, final long ttl) {
    record.setTTL(ttl);
  }


  public static List<Message> splitMessage(final Message message) {
    List<Message> messages = new ArrayList<>();

    int maxRecords = Options.intValue("mdns_max_records_per_message");
    if (maxRecords > 1) {
      maxRecords = 10;
    }

    Message m = null;
    for (int section : new int[]{0, 1, 2, 3}) {
      Record[] records = message.getSectionArray(section);
      for (int index = 0; index < records.length; index++) {
        if (m == null) {
          m = new Message();
          Header header = (Header) message.getHeader().clone();
          header.setCount(0, 0);
          header.setCount(1, 0);
          header.setCount(2, 0);
          header.setCount(3, 0);
          m.setHeader(header);
          m.addRecord(records[index], section);
        } else {
          m.addRecord(records[index], section);
        }

        // Only aggregate "mdns_max_records_per_message" or 10 questions into a single, to prevent large messages.
        if ((index != 0) && ((index % maxRecords) == 0)) {
          messages.add(m);
          m = null;
        }
      }
    }

    return messages;
  }
}
