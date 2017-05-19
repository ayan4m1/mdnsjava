package net.posick.mDNS.resolvers;

import java.util.function.Supplier;
import net.posick.mDNS.MulticastDNSCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;

/**
 * Resolver Listener used cache responses received from the network.
 *
 * @author Steve Posick
 */
public class Cacher implements ResolverListener {

  private final boolean mdnsVerbose;
  private final Supplier<Boolean> ignoreTruncation;
  private final MulticastDNSCache cache;

  public Cacher(final boolean mdnsVerbose, final Supplier<Boolean> ignoreTruncation,
      MulticastDNSCache cache) {
    this.mdnsVerbose = mdnsVerbose;
    this.ignoreTruncation = ignoreTruncation;
    this.cache = cache;
  }

  private static final Logger LOG = LoggerFactory.getLogger(Cacher.class);

  public void handleException(final Object id, final Exception e) {
  }

  public void receiveMessage(final Object id, final Message message) {
    Header header = message.getHeader();
    int rcode = message.getRcode();
    int opcode = header.getOpcode();

    if (ignoreTruncation.get() && header.getFlag(Flags.TC)) {
      LOG.warn("Receive - Truncated Message Ignored : " + "RCode: " + Rcode.string(rcode) + "; Opcode: " + Opcode
          .string(opcode));
      return;
    }

    switch (opcode) {
      case Opcode.IQUERY:
      case Opcode.QUERY:
      case Opcode.NOTIFY:
      case Opcode.STATUS:
        if (header.getFlag(Flags.QR) || header.getFlag(Flags.AA)) {
          cache.updateCache(MulticastDNSUtils
                  .extractRecords(message, Section.ANSWER, Section.AUTHORITY, Section.ADDITIONAL),
              Credibility.NONAUTH_AUTHORITY);
        } else {
          return;
        }
        break;
      case Opcode.UPDATE:
        // We do not allow updates from the network!
        LOG.error("Updates from the network are not allowed!");
        return;
    }

    if (mdnsVerbose) {
      LOG.info("Receive - RCode: " + Rcode.string(rcode));
      LOG.info("Receive - Opcode: " + Opcode.string(opcode));
    }
  }
}