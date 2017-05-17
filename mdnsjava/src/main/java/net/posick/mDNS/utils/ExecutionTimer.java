package net.posick.mDNS.utils;

import java.util.EmptyStackException;
import java.util.Stack;
import java.util.concurrent.TimeUnit;

@SuppressWarnings({"rawtypes", "unchecked"})
public class ExecutionTimer {

  private static ExecutionTimer timer = new ExecutionTimer();

  private final Stack stack = new Stack();


  public ExecutionTimer() {
  }


  public long start() {
    return (Long) stack.push(System.nanoTime());
  }


  public double took(final TimeUnit unit) {
    try {
      long start = (Long) stack.pop();
      long took = System.nanoTime() - start;

      switch (unit) {
        case DAYS:
          return (double) took / (double) 86400000000000L;
        case HOURS:
          return (double) took / (double) 3600000000000L;
        case MICROSECONDS:
          return (double) took / (double) 1000;
        case MILLISECONDS:
          return (double) took / (double) 1000000;
        case MINUTES:
          return (double) took / (double) 60000000000L;
        case NANOSECONDS:
          return took;
        case SECONDS:
          return (double) took / (double) 1000000000;
      }
    } catch (EmptyStackException e) {
      // ignore
    }

    return 0;
  }


  public static long _start() {
    return timer.start();
  }


  public static double _took(final TimeUnit unit) {
    return timer.took(unit);
  }
}
