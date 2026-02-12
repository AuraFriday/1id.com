package com.oneid.keycloak;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for the 1id.com Authentication Event Listener.
 *
 * Registered via META-INF/services/org.keycloak.events.EventListenerProviderFactory
 */
public class OneIdAuthEventListenerFactory implements EventListenerProviderFactory {

  public static final String PROVIDER_ID = "oneid-auth-event-listener";

  @Override
  public EventListenerProvider create(KeycloakSession session) {
    return new OneIdAuthEventListener();
  }

  @Override
  public void init(Config.Scope config) {
    // No initialization needed
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // No post-initialization needed
  }

  @Override
  public void close() {
    // No resources to clean up
  }

  @Override
  public String getId() { return PROVIDER_ID; }
}
