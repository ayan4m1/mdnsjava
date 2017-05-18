package net.posick.mDNS;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;
import org.xbill.DNS.Name;
import org.xbill.DNS.TextParseException;

public class ServiceName extends Name {

  private static final long serialVersionUID = 201305151047L;

  private static final byte[][] PROTOCOLS;

  private static final byte[] SUB_SERVICE_INDICATOR = {4, '_', 's', 'u', 'b'};

  static {
    List<byte[]> protocols = new ArrayList<>();
    byte[][] DEFAULTS = {{4, '_', 't', 'c', 'p'}, {4, '_', 'u', 'd', 'p'},
        {5, '_', 's', 'c', 't', 'p'}};
    Collections.addAll(protocols, DEFAULTS);

    URL url = ServiceName.class.getResource("ServiceName.protocol");
    BufferedReader data = null;
    try {
      data = new BufferedReader(new InputStreamReader(url.openStream()));

      String line = null;
      while ((line = data.readLine()) != null) {
        byte[] bytes = line.trim().getBytes();
        byte[] protocol = new byte[bytes.length + 1];
        protocol[0] = (byte) bytes.length;
        System.arraycopy(bytes, 0, protocol, 1, bytes.length);
        protocols.add(protocol);
      }
    } catch (Exception e) {
      Logger.getAnonymousLogger()
          .log(Level.FINE, "Could not find Protocols file \"" + url + "\"", e);
    } finally {
      IOUtils.closeQuietly(data);
    }
    PROTOCOLS = protocols.toArray(new byte[protocols.size()][]);
  }

  private String instance;
  private String fullSubType;
  private String subType;
  private String fullType;
  private String type;
  private String domain;
  private String protocol;
  private String application;
  private final Name serviceTypeName;
  private final Name serviceRRName;

  public ServiceName(final String s) throws TextParseException {
    this(new Name(s));
  }

  public ServiceName(final String s, final Name name) throws TextParseException {
    this(new Name(s, name));
  }

  ServiceName(final Name name) throws TextParseException {
    super(name, 0);

    byte[] super_name = null;
    try {
      Class<Name> cls = Name.class;
      Field field = cls.getDeclaredField("name");
      field.setAccessible(true);
      super_name = (byte[]) field.get(name);
    } catch (NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
      // ignore
    }

    int labelCount = name.labels();
    if (super_name == null) {
      // Reconstruct the name byte array if the reflective method fails.
      super_name = new byte[name.length()];
      int current = 0;
      for (int index = 0; index < labelCount; index++) {
        byte[] label = name.getLabel(index);
        System.arraycopy(label, 0, super_name, current, label[0] + 1);
        current += label[0] + 1;
      }
    }

    short[] offsets = new short[labelCount];

    short offset = 0;
    int serviceParts = 0;
    int serviceStartIndex = -1;
    int subTypeIndex = -1;
    int serviceEndIndex = -1;
    for (int index = 0; index < labelCount; index++) {
      offsets[index] = offset;
      short length = (short) (super_name[offsets[index]] & 0x0FF);
      offset = (short) (offsets[index] + length + 1);

      if (super_name[offsets[index]] > 0 && super_name[offsets[index] + 1] == '_') {
        if (serviceEndIndex < 0) {
          serviceEndIndex = index;
        }
        if (subTypeIndex < 0 && arrayEquals(SUB_SERVICE_INDICATOR, super_name, offsets[index])) {
          subTypeIndex = index;
        }
        serviceStartIndex = index;
        serviceParts++;
      }
    }

    if (serviceParts > 0) {
      StringBuilder builder = new StringBuilder();
      if (serviceEndIndex > 0) {
        for (int index = 0; index < serviceEndIndex; index++) {
          int length = super_name[offsets[index]];
          if (length > 0) {
            builder.append(new String(super_name, offsets[index] + 1, length)).append('.');
          }
        }
        this.instance = builder.substring(0, builder.length() - 1);
        builder.setLength(0);
      }
      for (int index = serviceEndIndex; index <= serviceStartIndex; index++) {
        int length = super_name[offsets[index]];
        if (length > 0) {
          String temp = new String(super_name, offsets[index] + 1, length);
          if (index < subTypeIndex) {
            builder.append(temp);
          } else if (index == subTypeIndex) {
            this.subType = builder.substring(0, builder.length() - 1);
            builder.append(temp);
            this.fullSubType = builder.toString();
          } else if (index == serviceStartIndex) {
            builder.append(temp);
            for (byte[] PROTOCOL : PROTOCOLS) {
              if (arrayEquals(PROTOCOL, super_name, offsets[index])) {
                this.protocol = temp;
                break;
              }
            }
            break;
          } else {
            builder.append(temp);
          }
          builder.append('.');
        }
      }
      if (this.fullSubType != null) {
        this.type = builder.substring(this.fullSubType.length() + 1, builder.length());
        this.fullType = builder.toString();
        if (this.protocol != null) {
          this.application = builder
              .substring(this.fullSubType.length() + 1, builder.length() - protocol.length() - 1);
        } else {
          this.application = this.type;
        }
      } else {
        this.type = this.fullType = builder.toString();
        if (this.protocol != null) {
          this.application = builder.substring(0, builder.length() - protocol.length() - 1);
        } else {
          this.application = this.type;
        }
      }
      builder.setLength(0);
      for (int index = serviceStartIndex + 1; index < offsets.length; index++) {
        int length = super_name[offsets[index]];
        if (length > 0) {
          builder.append(new String(super_name, offsets[index] + 1, length)).append('.');
        }
      }
      this.domain = builder.substring(0, builder.length());
      builder.setLength(0);
      this.serviceTypeName = new Name(this.type + (this.domain != null ? "." + this.domain : ""));
      if (this.instance != null && this.instance.length() > 0) {
        this.serviceRRName = new Name(this.instance, this.serviceTypeName);
      } else {
        this.serviceRRName = null;
      }
    } else {
      throw new TextParseException(
          "Name \"" + name + "\" is not an IETF RFC 2782 or IETF RFC 6763 compliant service name.");
    }
  }


  private static final boolean arrayEquals(byte[] test, byte[] src, short offset) {
    short length = src[offset];
    if (length == test[0] && src.length > offset + length) {
      for (int index = 1; index < length; index++) {
        if (test[index] != src[offset + index]) {
          return false;
        }
      }
      return true;
    }
    return false;
  }


  public String getApplication() {
    return application;
  }


  public String getDomain() {
    return domain;
  }


  public String getFullSubType() {
    return fullSubType;
  }


  public String getFullType() {
    return fullType;
  }


  public String getInstance() {
    return instance;
  }


  public String getProtocol() {
    return protocol;
  }


  public Name getServiceTypeName() {
    return serviceTypeName;
  }


  public Name getServiceRRName() {
    return serviceRRName;
  }


  public String getSubType() {
    return subType;
  }


  public String getType() {
    return type;
  }
}
