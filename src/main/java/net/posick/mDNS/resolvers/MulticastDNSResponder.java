package net.posick.mDNS.resolvers;

import static net.posick.mDNS.utils.MessageWriter.writeResponse;

import java.io.IOException;
import java.util.List;
import java.util.function.Supplier;
import net.posick.mDNS.MulticastDNSCache;
import net.posick.mDNS.net.DatagramProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Credibility;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Opcode;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;

/**
 * Resolver Listener that replies to queries from the network.
 *
 * @author Steve Posick
 */
public class MulticastDNSResponder implements ResolverListener {

  private static final Logger LOG = LoggerFactory.getLogger(MulticastDNSResponder.class);

  private final boolean mdnsVerbose;
  private final Supplier<Boolean> ignoreTruncation;
  private final MulticastDNSCache cache;
  private final List<DatagramProcessor> multicastProcessors;
  private final ResolverListener resolverListenerDispatcher;
  private final TSIG tsig;
  private final OPTRecord optRecord;

  public MulticastDNSResponder(final boolean mdnsVerbose, final Supplier<Boolean> ignoreTruncation,
      MulticastDNSCache cache, List<DatagramProcessor> multicastProcessors,
      ResolverListener resolverListenerDispatcher, TSIG tsig, OPTRecord optRecord)
      throws IOException {
    this.mdnsVerbose = mdnsVerbose;
    this.ignoreTruncation = ignoreTruncation;
    this.cache = cache;
    this.multicastProcessors = multicastProcessors;
    this.resolverListenerDispatcher = resolverListenerDispatcher;
    this.tsig = tsig;
    this.optRecord = optRecord;
  }

  public void handleException(final Object id, final Exception e) {
  }

  public void receiveMessage(final Object id, final Message message) {
    int rcode = message.getRcode();
    Header header = message.getHeader();
    int opcode = header.getOpcode();

    if (header.getFlag(Flags.QR) || header.getFlag(Flags.AA)) {
      return;
    }

    if (header.getFlag(Flags.TC)) {
      if (ignoreTruncation.get()) {
        LOG.warn("Truncated Message : " + "RCode: " + Rcode.string(rcode) + "; Opcode: " + Opcode
            .string(opcode) + " - Ignoring subsequent known answer records.");
        return;
      } else {
        // TODO: Implement the reception of truncated packets. (wait 400 to 500 milliseconds for more known answers)
      }
    }

    if (mdnsVerbose) {
      LOG.info("Receive - RCode: " + Rcode.string(rcode));
      LOG.info("Receive - Opcode: " + Opcode.string(opcode));
    }

    try {
      switch (opcode) {
        case Opcode.IQUERY:
        case Opcode.QUERY:
          Message response = cache.queryCache(message, Credibility.AUTH_AUTHORITY);

          if (response != null) {
            Header responseHeader = response.getHeader();
            if ((responseHeader.getCount(Section.ANSWER) > 0) || (
                responseHeader.getCount(Section.AUTHORITY) > 0) || (
                responseHeader.getCount(Section.ADDITIONAL) > 0)) {
              if (mdnsVerbose) {
                LOG.info("Receive - Query Reply ID: " + id + "\n" + response);
              }
              responseHeader.setFlag(Flags.AA);
              responseHeader.setFlag(Flags.QR);
              writeResponse(response, multicastProcessors, resolverListenerDispatcher, tsig, optRecord);
            } else {
              if (mdnsVerbose) {
                LOG.info("Receive - No response, client knows answer.");
              }
            }
          }
          break;
        case Opcode.NOTIFY:
        case Opcode.STATUS:
        case Opcode.UPDATE:
          LOG.warn("Receive - Received Invalid Request - Opcode: " + Opcode.string(opcode));
          break;
      }
    } catch (Exception e) {
      LOG.error("Error replying to query", e);
    }
  }



}

