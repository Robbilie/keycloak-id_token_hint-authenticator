package de.eneticum.keycloak;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.utils.StringUtil;

public class IdTokenHintAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        String idTokenHint = authenticationFlowContext.getSession().getContext().getUri().getQueryParameters().getFirst(OIDCLoginProtocol.ID_TOKEN_HINT);
        if (StringUtil.isBlank(idTokenHint)) {
            authenticationFlowContext.attempted();
            return;
        }

        try {
            JWSInput jws = new JWSInput(idTokenHint);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);

            // TODO: needs to be validated

            UserModel user = authenticationFlowContext.getSession().users().getUserById(authenticationFlowContext.getRealm(), token.getSubject());

            if (user == null) {
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_USER);
                return;
            }

            authenticationFlowContext.setUser(user);
            authenticationFlowContext.success();

        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
        }
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}
