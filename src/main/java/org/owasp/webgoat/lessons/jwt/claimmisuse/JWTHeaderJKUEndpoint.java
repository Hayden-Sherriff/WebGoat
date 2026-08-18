/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Objects;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;

@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {

  private final List<URI> allowedJwksUrls;

  public JWTHeaderJKUEndpoint(
      @Value("${webgoat.jwt.jku.allowed-urls:}") List<String> allowedJwksUrls) {
    this.allowedJwksUrls =
        allowedJwksUrls.stream()
            .map(String::trim)
            .filter(StringUtils::isNotEmpty)
            .map(JWTHeaderJKUEndpoint::toNormalizedUri)
            .filter(Objects::nonNull)
            .toList();
  }

  @PostMapping("/JWT/jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("/JWT/jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        var decodedJWT = JWT.decode(token);
        var jku = decodedJWT.getHeaderClaim("jku");
        var jwksUrl = resolveAllowedJwksUrl(jku.asString());
        if (jwksUrl == null) {
          return failed(this)
              .feedback("jwt-invalid-token")
              .output("The 'jku' header does not point to a trusted JWKS location")
              .build();
        }
        var jwkProvider = new JwkProviderBuilder(jwksUrl.toURL()).build();
        var jwk = jwkProvider.get(decodedJWT.getKeyId());
        var algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey());
        JWT.require(algorithm).build().verify(decodedJWT);

        var username = decodedJWT.getClaims().get("username").asString();
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (MalformedURLException | JWTVerificationException | JwkException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }

  /**
   * Returns the configured JWKS location matching the given {@code jku} claim, or {@code null} when
   * the claim does not exactly match one of the trusted locations. No outbound request is made for
   * untrusted values.
   */
  private URI resolveAllowedJwksUrl(String jku) {
    if (StringUtils.isEmpty(jku)) {
      return null;
    }
    var requested = toNormalizedUri(jku);
    if (requested == null) {
      return null;
    }
    return allowedJwksUrls.stream().filter(requested::equals).findFirst().orElse(null);
  }

  private static URI toNormalizedUri(String url) {
    try {
      var uri = new URI(url).normalize();
      return uri.isAbsolute() ? uri : null;
    } catch (URISyntaxException e) {
      return null;
    }
  }
}
