/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_READ_ONLY;
import static java.sql.ResultSet.TYPE_SCROLL_INSENSITIVE;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.regex.Pattern;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(value = {"SqlStringInjectionHint3-1", "SqlStringInjectionHint3-2"})
public class SqlInjectionLesson3 implements AssignmentEndpoint {

  private final LessonDataSource dataSource;

  // The lesson is solved with a single UPDATE against the local, unqualified "employees" table.
  private static final Pattern SAFE_UPDATE =
      Pattern.compile(
          "^\\s*UPDATE\\s+employees\\s+SET\\s+.+", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  // DDL / routine / privilege / cross-schema constructs that could escalate beyond the lesson.
  private static final Pattern FORBIDDEN =
      Pattern.compile(
          "\\b(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|ALIAS|CALL|SCRIPT|SHUTDOWN|BACKUP|CHECKPOINT"
              + "|INSERT|DELETE|MERGE|CONTAINER)\\b",
          Pattern.CASE_INSENSITIVE);

  public SqlInjectionLesson3(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  /**
   * Restricts the executed statement to the operation this lesson teaches: a single UPDATE of the
   * local {@code employees} table. Stacked statements, DDL, {@code CREATE ALIAS}, privilege
   * changes and cross-schema references are rejected so injection cannot reach other schemas or
   * define Java routines.
   */
  private static boolean isAllowedLessonQuery(String query) {
    if (query == null) {
      return false;
    }
    String normalized = query.trim();
    if (normalized.endsWith(";")) {
      normalized = normalized.substring(0, normalized.length() - 1).trim();
    }
    // Reject stacked/compound statements.
    if (normalized.contains(";")) {
      return false;
    }
    if (!SAFE_UPDATE.matcher(normalized).matches()) {
      return false;
    }
    return !FORBIDDEN.matcher(normalized.toUpperCase(Locale.ROOT)).find();
  }

  @PostMapping("/SqlInjection/attack3")
  @ResponseBody
  public AttackResult completed(@RequestParam String query) {
    return injectableQuery(query);
  }

  protected AttackResult injectableQuery(String query) {
    if (!isAllowedLessonQuery(query)) {
      return failed(this)
          .output(
              "Only a single UPDATE statement against the employees table is allowed for this"
                  + " lesson.")
          .build();
    }
    try (Connection connection = dataSource.getConnection()) {
      try (Statement statement =
          connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY)) {
        Statement checkStatement =
            connection.createStatement(TYPE_SCROLL_INSENSITIVE, CONCUR_READ_ONLY);
        statement.executeUpdate(query);
        ResultSet results =
            checkStatement.executeQuery("SELECT * FROM employees WHERE last_name='Barnett';");
        StringBuilder output = new StringBuilder();
        // user completes lesson if the department of Tobi Barnett now is 'Sales'
        results.first();
        if (results.getString("department").equals("Sales")) {
          output.append("<span class='feedback-positive'>" + query + "</span>");
          output.append(SqlInjectionLesson8.generateTable(results));
          return success(this).output(output.toString()).build();
        } else {
          return failed(this).output(output.toString()).build();
        }

      } catch (SQLException sqle) {
        return failed(this).output(sqle.getMessage()).build();
      }
    } catch (Exception e) {
      return failed(this).output(this.getClass().getName() + " : " + e.getMessage()).build();
    }
  }
}
