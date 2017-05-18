package net.posick.mDNS.utils;

import com.google.common.primitives.Ints;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import net.posick.mDNS.net.NetworkProcessor;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Options;

public class Executors {

  private static final Logger LOG = LoggerFactory.getLogger(Executors.class);

  public static final int DEFAULT_NETWORK_THREAD_PRIORITY = Thread.NORM_PRIORITY + 2;

  public static final int CORE_THREADS_NETWORK_EXECUTOR = 5;

  public static final int MAX_THREADS_NETWORK_EXECUTOR = Integer.MAX_VALUE;

  public static final int TTL_THREADS_NETWORK_EXECUTOR = 10000;

  public static final int QUEUE_SIZE_NETWORK_EXECUTOR = 50;

  public static final int DEFAULT_CACHED_THREAD_PRIORITY = Thread.NORM_PRIORITY;

  public static final int CORE_THREADS_CACHED_EXECUTOR = 5;

  public static final int MAX_THREADS_CACHED_EXECUTOR = Integer.MAX_VALUE;

  public static final int TTL_THREADS_CACHED_EXECUTOR = 10000;

  public static final int QUEUE_SIZE_CACHED_EXECUTOR = 5;

  public static final int DEFAULT_SCHEDULED_THREAD_PRIORITY = Thread.NORM_PRIORITY;

  public static final int CORE_THREADS_SCHEDULED_EXECUTOR = 5;

  public static final int MAX_THREADS_SCHEDULED_EXECUTOR = Integer.MAX_VALUE;

  public static final int TTL_THREADS_SCHEDULED_EXECUTOR = 10000;

  public static final TimeUnit THREAD_TTL_TIME_UNIT = TimeUnit.MILLISECONDS;

  private static Executors executors;

  private final ScheduledThreadPoolExecutor scheduledExecutor;

  private final ThreadPoolExecutor executor;

  private final ThreadPoolExecutor networkExecutor;


  private Executors() {
    scheduledExecutor = (ScheduledThreadPoolExecutor) java.util.concurrent.Executors
        .newScheduledThreadPool(CORE_THREADS_SCHEDULED_EXECUTOR, new ThreadFactory() {
          public Thread newThread(final Runnable r) {
            Thread t = new Thread(r, "mDNS Scheduled Thread");
            t.setDaemon(true);

            int threadPriority = tryParse(getThenTry("mdns_scheduled_thread_priority", "mdns_thread_priority"), DEFAULT_SCHEDULED_THREAD_PRIORITY);
            t.setPriority(threadPriority);
            t.setContextClassLoader(this.getClass().getClassLoader());
            return t;
          }
        });

    getThenSet("mdns_scheduled_core_threads", scheduledExecutor::setCorePoolSize);
    getThenSet("mdns_scheduled_max_threads", scheduledExecutor::setMaximumPoolSize);
    getThenSet("mdns_scheduled_thread_ttl", TTL_THREADS_SCHEDULED_EXECUTOR,
        val -> scheduledExecutor.setKeepAliveTime(val, THREAD_TTL_TIME_UNIT));

    scheduledExecutor.allowCoreThreadTimeOut(true);

    int cacheExecutorQueueSize = tryParse(getThenTry("mdns_cached_thread_queue_size", "mdns_thread_queue_size"), QUEUE_SIZE_CACHED_EXECUTOR);
    executor = new ThreadPoolExecutor(CORE_THREADS_CACHED_EXECUTOR, MAX_THREADS_CACHED_EXECUTOR,
        TTL_THREADS_CACHED_EXECUTOR, THREAD_TTL_TIME_UNIT,
        new ArrayBlockingQueue<>(cacheExecutorQueueSize),
        r -> {
          Thread t = new Thread(r, "mDNS Cached Thread");
          t.setDaemon(true);

          int threadPriority = tryParse(getThenTry("mdns_cached_thread_priority", "mdns_thread_priority"), DEFAULT_CACHED_THREAD_PRIORITY);
          t.setPriority(threadPriority);
          t.setContextClassLoader(NetworkProcessor.class.getClassLoader());
          return t;
        }, new RejectedExecutionHandler() {
      public void rejectedExecution(final Runnable r, final ThreadPoolExecutor executor) {
        LOG.warn("Network Processing Queue Rejected Packet it is FULL. [size: " + executor.getQueue()
                .size() + "]");
      }
    });

    getThenSet("mdns_executor_core_threads", executor::setCorePoolSize);
    getThenSet("mdns_executor_max_threads", executor::setMaximumPoolSize);
    getThenSet("mdns_executor_thread_ttl", TTL_THREADS_CACHED_EXECUTOR,
        val -> executor.setKeepAliveTime(val, THREAD_TTL_TIME_UNIT));

    executor.allowCoreThreadTimeOut(true);

    int networkExecutorQueueSize = tryParse(getThenTry("mdns_cached_thread_queue_size", "mdns_thread_queue_size"), QUEUE_SIZE_NETWORK_EXECUTOR);

    networkExecutor = new ThreadPoolExecutor(CORE_THREADS_NETWORK_EXECUTOR,
        MAX_THREADS_NETWORK_EXECUTOR,
        TTL_THREADS_NETWORK_EXECUTOR, THREAD_TTL_TIME_UNIT,
        new ArrayBlockingQueue<>(networkExecutorQueueSize),
        r -> {
          Thread t = new Thread(r, "Network Queue Processing Thread");
          t.setDaemon(true);
          int threadPriority = tryParse(getThenTry("mdns_network_thread_priority", "mdns_thread_priority"), DEFAULT_NETWORK_THREAD_PRIORITY);
          t.setPriority(threadPriority);
          t.setContextClassLoader(NetworkProcessor.class.getClassLoader());
          return t;
        });
    networkExecutor.setRejectedExecutionHandler((r, executor) -> {
      Thread t = executor.getThreadFactory().newThread(r);
      t.start();
    });

    getThenSet("mdns_network_core_threads", networkExecutor::setCorePoolSize);
    getThenSet("mdns_network_max_threads", networkExecutor::setMaximumPoolSize);
    getThenSet("mdns_network_thread_ttl", TTL_THREADS_NETWORK_EXECUTOR,
        val -> networkExecutor.setKeepAliveTime(val, THREAD_TTL_TIME_UNIT));

    networkExecutor.allowCoreThreadTimeOut(true);
  }

  public boolean isExecutorOperational() {
    return !executor.isShutdown() && !executor.isTerminated() && !executor.isTerminating();
  }

  public boolean isNetworkExecutorOperational() {
    return !networkExecutor.isShutdown() && !networkExecutor.isTerminated() && !networkExecutor
        .isTerminating();
  }

  public boolean isScheduledExecutorOperational() {
    return !scheduledExecutor.isShutdown() && !scheduledExecutor.isTerminated()
        && !scheduledExecutor.isTerminating();
  }

  public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
    return scheduledExecutor.schedule(command, delay, unit);
  }

  public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period,
      TimeUnit unit) {
    return scheduledExecutor.scheduleAtFixedRate(command, initialDelay, period, unit);
  }

  public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay,
      TimeUnit unit) {
    return scheduledExecutor.scheduleWithFixedDelay(command, initialDelay, delay, unit);
  }

  public void execute(Runnable command) {
    executor.execute(command);
  }

  public void executeNetworkTask(Runnable command) {
    networkExecutor.execute(command);
  }

  public static Executors newInstance() {
    if (executors == null) {
      executors = new Executors();
    }

    return executors;
  }

  private void getThenSet(String key, Consumer<Integer> executorConsumer) {
    getThenSet(key, null, executorConsumer);
  }

  private void getThenSet(String key, Integer defaultValue, Consumer<Integer> executorConsumer) {
    Optional<Integer> valueOptional = Optional.ofNullable(Options.value(key)).map(Ints::tryParse);
    if (defaultValue != null) {
      executorConsumer.accept(valueOptional.orElse(defaultValue));
    } else {
      valueOptional.ifPresent(executorConsumer);
    }
  }

  private Optional<String> getThenTry(String key, String tryKey) {
    return Optional.ofNullable(Optional.ofNullable(Options.value(key))
        .filter(StringUtils::isBlank).orElse(Options.value(tryKey)));
  }

  private int tryParse(Optional<String> toParse, int defaultValue) {
    return toParse.map(Ints::tryParse).orElse(defaultValue);
  }
}
