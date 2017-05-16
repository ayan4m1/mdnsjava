package net.posick.mDNS;

import org.xbill.DNS.Message;

public interface DNSSDListener {

  void serviceDiscovered(Object id, ServiceInstance service);

  void serviceRemoved(Object id, ServiceInstance service);

  void receiveMessage(Object id, Message m);

  void handleException(Object id, Exception e);
}
