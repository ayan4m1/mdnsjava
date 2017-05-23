package net.posick.mDNS.resolvers;

import net.posick.mDNS.utils.ListenerProcessor;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.ResolverListener;

/**
 * @author Steve Posick
 */
public class ListenerWrapper implements ResolverListener {
  private final Object id;
  private final Message query;
  private final ResolverListener listener;
  private final ListenerProcessor<ResolverListener> resolverListenerProcessor;

  public ListenerWrapper(final Object id, final Message query, final ResolverListener listener,
      ListenerProcessor<ResolverListener> resolverListenerProcessor) {
    this.id = id;
    this.query = query;
    this.listener = listener;
    this.resolverListenerProcessor = resolverListenerProcessor;
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
      resolverListenerProcessor.unregisterListener(this);
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
        resolverListenerProcessor.unregisterListener(this);
      }
    }
  }
}
