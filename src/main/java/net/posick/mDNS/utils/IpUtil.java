package net.posick.mDNS.utils;

import java.util.ArrayList;
import java.util.List;
import net.posick.mDNS.Constants;
import org.xbill.DNS.Name;

/**
 * Created by christopherhawley on 5/23/17.
 */
public class IpUtil {

  public static List<Name> getMulticastDomains(boolean ipv4, boolean ipv6) {
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

}
