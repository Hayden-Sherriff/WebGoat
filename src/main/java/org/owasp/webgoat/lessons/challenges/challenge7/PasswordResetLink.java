/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.util.Random;
import lombok.extern.slf4j.Slf4j;

/**
 * WARNING: DO NOT CHANGE FILE WITHOUT CHANGING .git contents
 */
@Slf4j
public class PasswordResetLink {

  public String createPasswordReset(String username, String key) {
    Random random = new Random();
    if (username.equalsIgnoreCase("admin")) {
      // Admin has a fix reset link
      random.setSeed(key.length());
    }
    return scramble(random, scramble(random, scramble(random, MD5.getHashString(username))));
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      log.info("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    log.info("Generation password reset link for {}", username);
    log.info("Created password reset link: {}", new PasswordResetLink().createPasswordReset(username, key));
  }
}
