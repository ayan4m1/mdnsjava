package net.posick.mDNS.model;

import org.xbill.DNS.Name;

/**
 * Created by christopherhawley on 5/23/17.
 */
public class Domain {
  private final Name name;
  private final boolean isDefault;
  private final boolean isLegacy;

  public Domain(final Name name) {
    this.name = name;

    byte[] label = name.getLabel(0);
    isDefault = (char)label[0] == 'd';
    isLegacy = (char)label[0] == 'l';
  }

  public Name getName() {
    return name;
  }

  public boolean isDefault() {
    return isDefault;
  }

  public boolean isLegacy() {
    return isLegacy;
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  @Override
  public boolean equals(final Object obj) {
    if (obj == this) {
      return true;
    } else if (name == obj) {
      return true;
    } else if (obj instanceof Domain) {
      return name.equals(((Domain) obj).name);
    }

    return false;
  }

  @Override
  public String toString() {
    return name + (isDefault ? "  [default]" : "") + (isLegacy ? "  [legacy]" : "");
  }
}