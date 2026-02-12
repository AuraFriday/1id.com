package com.oneid.keycloak;

import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * 1id.com Trust Tier Protocol Mapper
 *
 * Injects 1id-specific claims into JWT access tokens and ID tokens:
 *   - trust_tier:             sovereign | legacy | virtual | declared
 *   - handle:                 @vanity_name or @1id_XXXXXXXX
 *   - tpm_manufacturer:       INTC | AMD | IFX | null (for declared)
 *   - ek_fingerprint_prefix:  first 4 hex chars of EK SHA-256
 *   - registered_at:          ISO 8601 timestamp
 *
 * Data source: queries the 'oneid' MySQL database (same MySQL instance
 * as Keycloak, separate database).
 *
 * The mapper looks up the identity using the Keycloak client_id,
 * which matches identities.keycloak_client_id in the oneid database.
 */
public class OneIdTrustTierProtocolMapper extends AbstractOIDCProtocolMapper
    implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

  private static final Logger logger = Logger.getLogger(OneIdTrustTierProtocolMapper.class.getName());

  public static final String PROVIDER_ID = "oneid-trust-tier-mapper";
  public static final String DISPLAY_TYPE = "1ID Trust Tier";
  public static final String DISPLAY_CATEGORY = "Token mapper";
  public static final String HELP_TEXT = "Injects 1id.com identity claims (trust_tier, handle, tpm_manufacturer, ek_fingerprint_prefix, registered_at) into the token.";

  // SECURITY: credentials read from environment variables (set in Keycloak's systemd unit)
  private static final String ONEID_DB_URL = System.getenv("ONEID_DB_URL") != null
      ? System.getenv("ONEID_DB_URL") : "jdbc:mysql://127.0.0.1:3306/oneid";
  private static final String ONEID_DB_USER = System.getenv("ONEID_DB_USER") != null
      ? System.getenv("ONEID_DB_USER") : "oneid";
  private static final String ONEID_DB_PASSWORD = System.getenv("ONEID_DB_PASSWORD") != null
      ? System.getenv("ONEID_DB_PASSWORD") : "";

  // SQL queries
  private static final String IDENTITY_QUERY =
      "SELECT i.internal_id, i.trust_tier, i.registered_at " +
      "FROM identities i " +
      "WHERE i.keycloak_client_id = ?";

  private static final String HANDLE_QUERY =
      "SELECT h.handle_name " +
      "FROM handles h " +
      "WHERE h.identity_internal_id = ? AND h.status = 'active' " +
      "ORDER BY h.registered_at ASC LIMIT 1";

  private static final String EK_QUERY =
      "SELECT e.tpm_manufacturer_code, LEFT(e.ek_fingerprint_sha256, 4) AS ek_prefix " +
      "FROM ek_registry e " +
      "WHERE e.identity_internal_id = ? AND e.revoked_at IS NULL " +
      "ORDER BY e.bound_at ASC LIMIT 1";

  private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

  @Override
  public String getDisplayCategory() { return DISPLAY_CATEGORY; }

  @Override
  public String getDisplayType() { return DISPLAY_TYPE; }

  @Override
  public String getHelpText() { return HELP_TEXT; }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() { return configProperties; }

  @Override
  public String getId() { return PROVIDER_ID; }

  @Override
  protected void setClaim(IDToken token, ProtocolMapperModel mappingModel,
                          UserSessionModel userSession, KeycloakSession keycloakSession,
                          ClientSessionContext clientSessionCtx) {

    // The client_id in Keycloak matches our keycloak_client_id column
    String keycloak_client_id = clientSessionCtx.getClientSession()
        .getClient().getClientId();

    try (Connection connection = DriverManager.getConnection(
        ONEID_DB_URL, ONEID_DB_USER, ONEID_DB_PASSWORD)) {

      // --- Look up identity ---
      String internal_id = null;
      String trust_tier = null;
      String registered_at = null;

      try (PreparedStatement identity_statement = connection.prepareStatement(IDENTITY_QUERY)) {
        identity_statement.setString(1, keycloak_client_id);
        try (ResultSet identity_result_set = identity_statement.executeQuery()) {
          if (identity_result_set.next()) {
            internal_id = identity_result_set.getString("internal_id");
            trust_tier = identity_result_set.getString("trust_tier");
            java.sql.Timestamp registered_timestamp = identity_result_set.getTimestamp("registered_at");
            if (registered_timestamp != null) {
              registered_at = registered_timestamp.toInstant().toString();
            }
          }
        }
      }

      if (internal_id == null) {
        // Not a 1id-enrolled agent -- skip claim injection
        logger.fine("No 1id identity found for client_id: " + keycloak_client_id);
        return;
      }

      // --- Set sub claim to 1id internal ID ---
      token.setSubject(internal_id);

      // --- Set trust_tier ---
      token.getOtherClaims().put("trust_tier", trust_tier);

      // --- Set registered_at ---
      if (registered_at != null) {
        token.getOtherClaims().put("registered_at", registered_at);
      }

      // --- Look up active handle ---
      String display_handle = "@" + internal_id;  // default: random handle
      try (PreparedStatement handle_statement = connection.prepareStatement(HANDLE_QUERY)) {
        handle_statement.setString(1, internal_id);
        try (ResultSet handle_result_set = handle_statement.executeQuery()) {
          if (handle_result_set.next()) {
            display_handle = "@" + handle_result_set.getString("handle_name");
          }
        }
      }
      token.getOtherClaims().put("handle", display_handle);

      // --- Look up EK info (for non-declared tiers) ---
      if (!"declared".equals(trust_tier)) {
        try (PreparedStatement ek_statement = connection.prepareStatement(EK_QUERY)) {
          ek_statement.setString(1, internal_id);
          try (ResultSet ek_result_set = ek_statement.executeQuery()) {
            if (ek_result_set.next()) {
              String tpm_manufacturer = ek_result_set.getString("tpm_manufacturer_code");
              String ek_fingerprint_prefix = ek_result_set.getString("ek_prefix");
              if (tpm_manufacturer != null) {
                token.getOtherClaims().put("tpm_manufacturer", tpm_manufacturer);
              }
              if (ek_fingerprint_prefix != null) {
                token.getOtherClaims().put("ek_fingerprint_prefix", ek_fingerprint_prefix);
              }
            }
          }
        }
      }

      logger.info("1id claims injected for " + internal_id +
          " (tier=" + trust_tier + ", handle=" + display_handle + ")");

    } catch (Exception database_error) {
      logger.log(Level.WARNING,
          "Failed to look up 1id identity for client " + keycloak_client_id,
          database_error);
      // Fail open: token is issued without 1id claims rather than blocking auth
    }
  }
}
