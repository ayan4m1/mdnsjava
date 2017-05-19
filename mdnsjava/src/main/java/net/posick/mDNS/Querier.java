/**
 *
 */
package net.posick.mDNS;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.ResolverListener;

/**
 * The Querier is an extension of the Resolver for asynchronous, multicast name resolution,
 * typically used for mDNS.
 *
 * @author Steve Posick
 */
public interface Querier extends Resolver, Closeable {

  int DEFAULT_UDPSIZE = 512;
  int DEFAULT_TIMEOUT = 6 * 1000;
  int DEFAULT_RESPONSE_WAIT_TIME = 500;
  int DEFAULT_RETRY_INTERVAL = 1000;

  /**
   * Broadcasts a name resolution query to the network, returning immediately. The response(s)
   * are delegated to the ResolverListeners registered via the registerListener operation or
   * that are browsing for a similar query.
   *
   * @param message The message to broadcast.
   * @param addKnownAnswers Add known records to the request for the Known-Answer Suppression, as
   * per RFC 6762.
   * @throws IOException If an exception occurs during the broadcast.
   */
  void broadcast(Message message, boolean addKnownAnswers) throws IOException;

  /**
   * @return The Mulitcast domains pertinent for this Responder
   */
  List<Name> getMulticastDomains();

  /**
   * @return true is IPv4 is enabled
   */
  boolean isIPv4();

  /**
   * @return true is IPv6 is enabled
   */
  boolean isIPv6();

  /**
   * @return true if the Querier is fully operational, all threads and executors are running
   */
  boolean isOperational();

  /**
   * Registers a ResolverListener that receives asynchronous name resolution requests and responses.
   * Once set, the Resolver will receive responses until the listener is unregistered. The listener
   * receives all mDNS datagrams, regardless of type or name.
   *
   * @param listener ResolverListener that receives asynchronous name resolution requests and
   * responses.
   * @return The listener if added, otherwise null. Note, the returned listener may be a new object
   */
  ResolverListener registerListener(ResolverListener listener);

  /**
   * Sets the minimum amount of time to wait for mDNS responses, between retries, when the
   * query is not fully cached.
   *
   * @param secs Number of seconds
   */
  void setRetryWaitTime(int secs);

  /**
   * Sets the minimum amount of time to wait for mDNS responses, between retries, when the
   * query is not fully cached.
   *
   * @param secs Number of seconds
   * @param msecs Number of milliseconds
   */
  void setRetryWaitTime(int secs, int msecs);

  /**
   * Unregisters a ResolverListener, stopping it from receiving datagrams.
   *
   * @param listener The registered ResolverListener.
   * @return The listener object that was unregistered, null if the unregistration failed.
   */
  ResolverListener unregisterListener(ResolverListener listener);
}
