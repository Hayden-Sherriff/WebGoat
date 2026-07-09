/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.StreamException;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import com.thoughtworks.xstream.security.NoTypePermission;
import org.junit.jupiter.api.Test;

class VulnerableComponentsLessonTest {

  private final String strangeContact =
      "<contact class='dynamic-proxy'>\n"
          + "<interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>\n"
          + "  <handler class='java.beans.EventHandler'>\n"
          + "    <target class='java.lang.ProcessBuilder'>\n"
          + "      <command>\n"
          + "        <string>calc.exe</string>\n"
          + "      </command>\n"
          + "    </target>\n"
          + "    <action>start</action>\n"
          + "  </handler>\n"
          + "</contact>";
  private final String contact = "<contact>\n" + "</contact>";

  private XStream securedXStream() {
    XStream xstream = new XStream();
    xstream.setClassLoader(Contact.class.getClassLoader());
    xstream.alias("contact", ContactImpl.class);
    xstream.ignoreUnknownElements();
    xstream.addPermission(NoTypePermission.NONE);
    xstream.allowTypes(new Class[] {ContactImpl.class, String.class, Integer.class});
    return xstream;
  }

  @Test
  void testTransformation() {
    assertThat(securedXStream().fromXML(contact)).isNotNull();
  }

  @Test
  void testExploitPayloadIsBlocked() {
    XStream xstream = securedXStream();
    assertThatThrownBy(() -> xstream.fromXML(strangeContact))
        .isInstanceOf(ForbiddenClassException.class);
  }

  @Test
  void testIllegalPayload() {
    XStream xstream = securedXStream();
    assertThatThrownBy(() -> xstream.fromXML("bullssjfs")).isInstanceOf(StreamException.class);
  }
}
