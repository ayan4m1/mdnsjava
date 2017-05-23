package net.posick.mDNS.utils;

import com.google.common.collect.Sets;
import java.io.Closeable;
import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The ListenerSupport class implements a performant, thread safe, listener subsystem
 * that does not create temporary objects during the event dispatch process. The order in which
 * listeners are registered determines the order by which the listeners are called during event
 * dispatch. A listener may halt the delivery of events to subsequent listeners by throwing a
 * StopDispatchException.
 *
 * @author Steve Posick
 */
@SuppressWarnings("unchecked")
public class ListenerProcessor<T> implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(ListenerProcessor.class);

  public static class StopDispatchException extends Exception {
    private static final long serialVersionUID = 201401211841L;

    public StopDispatchException() {
      super();
    }
  }

  protected static class Dispatcher implements InvocationHandler {
    ListenerProcessor<?> processor;

    protected Dispatcher(final ListenerProcessor<?> processor) {
      this.processor = processor;
    }

    public Object invoke(final Object proxy, final Method method, final Object[] args)
        throws Throwable {
      for (Object listener : processor.listeners) {
        try {
          method.invoke(listener, args);
        } catch (IllegalArgumentException | IllegalAccessException e) {
          LOG.warn(e.getMessage(), e);
          throw e;
        } catch (InvocationTargetException e) {
          if (e.getTargetException() instanceof StopDispatchException) {
            break;
          } else {
            LOG.warn(e.getTargetException().getMessage(), e.getTargetException());
            throw e.getTargetException();
          }
        } catch (Exception e) {
          LOG.error(e.getMessage(), e);
          throw e;
        }
      }

      return null;
    }
  }

  private final Class<T> iface;
  private Set<Object> listeners = Sets.newConcurrentHashSet();
  private T dispatcher;

  public ListenerProcessor(final Class<T> iface) {
    this.iface = iface;
    if (!iface.isInterface()) {
      throw new IllegalArgumentException("\"" + iface.getName() + "\" is not an interface.");
    }
  }

  public T getDispatcher() {
    if (dispatcher == null) {
      dispatcher = (T) Proxy
          .newProxyInstance(getClass().getClassLoader(), new Class[]{iface}, new Dispatcher(this));
    }
    return dispatcher;
  }

  public T registerListener(final T listener) {
    // Make sure the listener is not null and that it implements the Interface
    if (listener != null && iface.isAssignableFrom(listener.getClass())) {
      this.listeners.add(listener);
      return listener;
    }

    return null;
  }

  public T unregisterListener(final T listener) {
    if (listener != null) {
      boolean removed = this.listeners.remove(listener);
      return removed ? listener : null;
    }

    return null;
  }

  @Override
  public void close() throws IOException {
    this.listeners.clear();
    this.listeners = Sets.newConcurrentHashSet();
  }
}
