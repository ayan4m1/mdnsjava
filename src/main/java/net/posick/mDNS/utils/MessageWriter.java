package net.posick.mDNS.utils;

import java.io.IOException;
import java.util.List;
import net.posick.mDNS.net.DatagramProcessor;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.MulticastDNSUtils;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.ResolverListener;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;

/**
 * Created by christopherhawley on 5/18/17.
 */
public class MessageWriter {

  private MessageWriter() {

  }
  /**
   * {@inheritDoc}
   */
  public static void writeResponse(final Message message, List<DatagramProcessor> multicastProcessors,
      ResolverListener resolverListenerDispatcher, TSIG tsig, OPTRecord queryOpt) throws IOException {
    Header header = message.getHeader();

    header.setFlag(Flags.AA);
    header.setFlag(Flags.QR);
    header.setRcode(0);

    writeMessageToWire(message, multicastProcessors, resolverListenerDispatcher, tsig, queryOpt);
  }


  public static void writeMessageToWire(final Message message, List<DatagramProcessor> multicastProcessors,
      ResolverListener resolverListenerDispatcher, TSIG tsig, OPTRecord queryOpt) throws IOException {
    Header header = message.getHeader();
    header.setID(0);
    applyEDNS(message, queryOpt);
    if (tsig != null) {
      tsig.apply(message, null);
    }

    byte[] out = message.toWire(Message.MAXLENGTH);
    for (DatagramProcessor multicastProcessor : multicastProcessors) {
      OPTRecord opt = message.getOPT();
      int maxUDPSize = opt == null ?  multicastProcessor.getMaxPayloadSize() : opt.getPayloadSize();

      if (out.length > maxUDPSize) {
        if (header.getFlag(Flags.QR)) {
          throw new IOException("DNS Message too large! - " + out.length + " bytes in size.");
        } else {
          List<Message> messages = MulticastDNSUtils.splitMessage(message);
          for (Message message1 : messages) {
            writeMessageToWire(message1, multicastProcessors, resolverListenerDispatcher, tsig, queryOpt);
          }
          return;
        }
      }

      try {
        multicastProcessor.send(out);
      } catch (Exception e) {
        resolverListenerDispatcher.handleException(message.getHeader().getID(), e);
      }
    }
  }

  private static void applyEDNS(final Message query, OPTRecord queryOPT) {
    if ((queryOPT == null) || (query.getOPT() != null)) {
      return;
    }
    query.addRecord(queryOPT, Section.ADDITIONAL);
  }

}
