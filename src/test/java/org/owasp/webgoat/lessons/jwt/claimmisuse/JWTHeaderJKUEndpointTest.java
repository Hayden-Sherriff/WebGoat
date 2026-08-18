/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static io.jsonwebtoken.SignatureAlgorithm.RS256;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.RsaJsonWebKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.webgoat.container.plugins.LessonTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class JWTHeaderJKUEndpointTest extends LessonTest {

  private static final WireMockServer trustedJwksServer =
      new WireMockServer(options().dynamicPort());
  private static final WireMockServer attackerServer = new WireMockServer(options().dynamicPort());

  private KeyPair keyPair;

  @BeforeAll
  static void startServers() {
    trustedJwksServer.start();
    attackerServer.start();
  }

  @AfterAll
  static void stopServers() {
    trustedJwksServer.stop();
    attackerServer.stop();
  }

  @DynamicPropertySource
  static void allowedJwksUrls(DynamicPropertyRegistry registry) {
    registry.add("webgoat.jwt.jku.allowed-urls", () -> trustedJwksUrl());
  }

  private static String trustedJwksUrl() {
    return "http://localhost:%d/files/jwks".formatted(trustedJwksServer.port());
  }

  private static String attackerJwksUrl() {
    return "http://localhost:%d/files/jwks".formatted(attackerServer.port());
  }

  @BeforeEach
  public void setup() throws Exception {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.wac).build();

    trustedJwksServer.resetAll();
    attackerServer.resetAll();
    this.keyPair = generateRsaKey();
  }

  private KeyPair generateRsaKey() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  @Test
  @DisplayName("A token verified against a trusted JWKS location is accepted")
  void solve() throws Exception {
    stubJsonWebKeySet(trustedJwksServer);
    var token = createTokenAndSignIt(trustedJwksUrl());

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(true)));
  }

  @Test
  @DisplayName("When the JWKS is not present at the trusted location then the call should fail")
  void shouldFailNotPresent() throws Exception {
    var token = createTokenAndSignIt(trustedJwksUrl());

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  @Test
  @DisplayName("A jku pointing to an untrusted host is rejected without any outbound request")
  void shouldRejectUntrustedJku() throws Exception {
    stubJsonWebKeySet(attackerServer);
    var token = createTokenAndSignIt(attackerJwksUrl());

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));

    attackerServer.verify(0, WireMock.getRequestedFor(WireMock.urlMatching("/files/jwks")));
  }

  @ParameterizedTest
  @MethodSource("jkusSharingATrustedPrefix")
  @DisplayName("A jku sharing the prefix of a trusted location is rejected")
  void shouldRejectJkuWithTrustedPrefix(String jku) throws Exception {
    stubJsonWebKeySet(attackerServer);
    var token = createTokenAndSignIt(jku);

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  private static Stream<String> jkusSharingATrustedPrefix() {
    return Stream.of(
        trustedJwksUrl() + ".attacker.example.com/jwks",
        "http://localhost.attacker.example.com:%d/files/jwks".formatted(trustedJwksServer.port()));
  }

  @Test
  @DisplayName("A token without a jku header is rejected")
  void shouldRejectMissingJku() throws Exception {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    var token =
        Jwts.builder().setClaims(claims).signWith(RS256, this.keyPair.getPrivate()).compact();

    mockMvc
        .perform(MockMvcRequestBuilders.post("/JWT/jku/delete").param("token", token).content(""))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.lessonCompleted", is(false)));
  }

  private String createTokenAndSignIt(String jku) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("username", "Tom");
    return Jwts.builder()
        .setHeaderParam("jku", jku)
        .setClaims(claims)
        .signWith(RS256, this.keyPair.getPrivate())
        .compact();
  }

  private void stubJsonWebKeySet(WireMockServer server) {
    var jwks = new JsonWebKeySet(new RsaJsonWebKey((RSAPublicKey) keyPair.getPublic()));
    server.stubFor(
        WireMock.get(WireMock.urlMatching("/files/jwks"))
            .willReturn(aResponse().withStatus(200).withBody(jwks.toJson())));
  }
}
