package com.oneid.keycloak;

import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 1id.com Authentication Event Listener
 *
 * On each CLIENT_LOGIN event in the 'agents' realm, updates
 * last_authentication_at in the identities table.
 *
 * This gives us "active 1IDs" metrics without logging what service
 * the agent authenticated to -- we do NOT log activity details,
 * just that the agent authenticated.
 */
public class OneIdAuthEventListener implements EventListenerProvider {

  private static final Logger logger = Logger.getLogger(OneIdAuthEventListener.class.getName());

  // SECURITY: credentials read from environment variables (set in Keycloak's systemd unit)
  private static final String ONEID_DB_URL = System.getenv("ONEID_DB_URL") != null
      ? System.getenv("ONEID_DB_URL") : "jdbc:mysql://127.0.0.1:3306/oneid";
  private static final String ONEID_DB_USER = System.getenv("ONEID_DB_USER") != null
      ? System.getenv("ONEID_DB_USER") : "oneid";
  private static final String ONEID_DB_PASSWORD = System.getenv("ONEID_DB_PASSWORD") != null
      ? System.getenv("ONEID_DB_PASSWORD") : "";

  private static final String UPDATE_LAST_AUTH_SQL =
      "UPDATE identities SET last_authentication_at = NOW() " +
      "WHERE keycloak_client_id = ?";

  @Override
  public void onEvent(Event event) {
    // Only care about client_credentials token issuance in the agents realm
    if (event.getType() == EventType.CLIENT_LOGIN
        && "agents".equals(event.getRealmName())) {

      String keycloak_client_id = event.getClientId();

      try (Connection connection = DriverManager.getConnection(
          ONEID_DB_URL, ONEID_DB_USER, ONEID_DB_PASSWORD);
           PreparedStatement update_statement = connection.prepareStatement(UPDATE_LAST_AUTH_SQL)) {

        update_statement.setString(1, keycloak_client_id);
        int rows_updated = update_statement.executeUpdate();

        if (rows_updated > 0) {
          logger.fine("Updated last_authentication_at for client: " + keycloak_client_id);
        }

      } catch (Exception database_error) {
        // Non-fatal: don't block authentication if metric update fails
        logger.log(Level.WARNING,
            "Failed to update last_authentication_at for " + keycloak_client_id,
            database_error);
      }
    }
  }

  @Override
  public void onEvent(AdminEvent adminEvent, boolean includeRepresentation) {
    // We don't need to track admin events
  }

  @Override
  public void close() {
    // No resources to clean up (connections are per-event)
  }
}
