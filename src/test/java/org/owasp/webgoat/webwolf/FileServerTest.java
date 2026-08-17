/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;

class FileServerTest {

  private static final String USERNAME = "webgoat";

  @TempDir Path fileLocation;

  private FileServer fileServer;
  private Authentication authentication;

  @BeforeEach
  void setup() {
    fileServer = new FileServer();
    ReflectionTestUtils.setField(fileServer, "fileLocation", fileLocation.toString());
    authentication = mock();
    when(authentication.getName()).thenReturn(USERNAME);
  }

  @Test
  @DisplayName("A normal file is stored in the directory of the user")
  void shouldStoreFileInUserDirectory() throws IOException {
    fileServer.importFile(multipartFile("test.txt"), authentication);

    assertThat(fileLocation.resolve(USERNAME).resolve("test.txt")).hasContent("content");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "../evil.txt",
        "../../evil.txt",
        "subdir/evil.txt",
        "/tmp/evil.txt",
        "..\\evil.txt",
        "C:\\evil.txt"
      })
  @DisplayName("A file name containing a path is reduced to its base name")
  void shouldStripPathFromFileName(String originalFileName) throws IOException {
    fileServer.importFile(multipartFile(originalFileName), authentication);

    assertThat(fileLocation.resolve(USERNAME).resolve("evil.txt")).hasContent("content");
    assertThat(Files.walk(fileLocation).filter(Files::isRegularFile)).hasSize(1);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", " ", ".", "..", "../..", "/", "..\\"})
  @DisplayName("A file name without a usable base name is rejected")
  void shouldRejectFileNameWithoutBaseName(String originalFileName) throws IOException {
    var multipartFile = multipartFile(originalFileName);

    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> fileServer.importFile(multipartFile, authentication));
    assertThat(Files.walk(fileLocation).filter(Files::isRegularFile)).isEmpty();
  }

  private MockMultipartFile multipartFile(String originalFileName) {
    return new MockMultipartFile("file", originalFileName, null, "content".getBytes());
  }
}
