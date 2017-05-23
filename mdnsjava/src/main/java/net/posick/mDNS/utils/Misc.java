package net.posick.mDNS.utils;

import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * This class contains miscellaneous utility methods
 *
 * @author Steve Posick
 */
public class Misc {

  /**
   * Returns the message and stack trace from the provided Throwable
   *
   * @param t The Throwable
   * @return The message and stack trace from the provided Throwable
   */
  public static String throwableToString(Throwable t) {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    t.printStackTrace(pw);
    return t.getMessage() + "\nStack Trace:\n" + sw.toString();
  }


  public static String unescape(String string) {
    if (string == null) {
      return null;
    }

    StringBuilder output = new StringBuilder();
    char[] chars = string.toCharArray();

    boolean escape = false;
    int codePoint = 0;
    int count = 0;

    for (char c : chars) {
      if (c == '\\') {
        escape = true;
        count = 2;
        codePoint = 0;
        continue;
      } else if (escape && count < 0) {
        escape = false;
        output.append((char) codePoint);
      }

      if (escape) {
        if (Character.isDigit(c)) {
          codePoint += ((int) c - '0') * Math.pow(10, count);
        }
      } else {
        output.append(c);
      }
      count--;
    }

    return output.toString();
  }
}
