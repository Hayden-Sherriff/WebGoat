/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SigningKeyResolverAdapter;
import io.jsonwebtoken.impl.TextCodec;

@RestController
@AssignmentHints({
  "jwt-kid-hint1",
  "jwt-kid-hint2",
  "jwt-kid-hint3",
  "jwt-kid-hint4",
  "jwt-kid-hint5",
  "jwt-kid-hint6"
})
public class JWTHeaderKIDEndpoint implements AssignmentEndpoint {
  private static final Pattern KID_PATTERN = Pattern.compile("[A-Za-z0-9_-]{1,64}");
  private static final String KID_QUERY = "SELECT key FROM jwt_keys WHERE id = ?";

  /**
   * Random key used when the key id cannot be resolved, so that verification fails instead of the
   * parser rejecting a null key with an IllegalArgumentException.
   */
  private static final byte[] UNRESOLVABLE_KEY = new byte[64];

  static {
    new SecureRandom().nextBytes(UNRESOLVABLE_KEY);
  }

  private final LessonDataSource dataSource;

  public JWTHeaderKIDEndpoint(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/JWT/kid/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("/JWT/kid/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    } else {
      try {
        Jwt jwt =
            Jwts.parser()
                .setSigningKeyResolver(
                    new SigningKeyResolverAdapter() {
                      @Override
                      public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                        final String kid = (String) header.get("kid");
                        if (kid == null || !KID_PATTERN.matcher(kid).matches()) {
                          return UNRESOLVABLE_KEY;
                        }
                        try (var connection = dataSource.getConnection();
                            var statement = connection.prepareStatement(KID_QUERY)) {
                          statement.setString(1, kid);
                          try (ResultSet rs = statement.executeQuery()) {
                            if (rs.next()) {
                              return TextCodec.BASE64.decode(rs.getString(1));
                            }
                          }
                        } catch (SQLException e) {
                          throw new IllegalStateException("Unable to resolve signing key", e);
                        }
                        return UNRESOLVABLE_KEY;
                      }
                    })
                .parseClaimsJws(token);
        Claims claims = (Claims) jwt.getBody();
        String username = (String) claims.get("username");
        if ("Jerry".equals(username)) {
          return failed(this).feedback("jwt-final-jerry-account").build();
        }
        if ("Tom".equals(username)) {
          return success(this).build();
        } else {
          return failed(this).feedback("jwt-final-not-tom").build();
        }
      } catch (JwtException e) {
        return failed(this).feedback("jwt-invalid-token").output(e.toString()).build();
      }
    }
  }
}
