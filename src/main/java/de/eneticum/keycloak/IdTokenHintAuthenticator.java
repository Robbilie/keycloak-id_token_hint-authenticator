package de.eneticum.keycloak;

import org.keycloak.TokenVerifier;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.IDToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.utils.StringUtil;

import java.security.PublicKey;

public class IdTokenHintAuthenticator implements Authenticator {
    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        String idTokenHint = authenticationFlowContext.getSession().getContext().getUri().getQueryParameters().getFirst(OIDCLoginProtocol.ID_TOKEN_HINT);
        if (StringUtil.isBlank(idTokenHint)) {
            authenticationFlowContext.attempted();
            return;
        }

        try {
            TokenVerifier<IDToken> idTokenTokenVerifier = createVerifier(idTokenHint, authenticationFlowContext);

            idTokenTokenVerifier.verify();

            IDToken idToken = idTokenTokenVerifier.getToken();

            UserModel user = authenticationFlowContext.getSession().users().getUserById(authenticationFlowContext.getRealm(), idToken.getSubject());

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

    private TokenVerifier<IDToken> createVerifier(String tokenString, AuthenticationFlowContext authenticationFlowContext) throws VerificationException {
        TokenVerifier<IDToken> idTokenTokenVerifier = TokenVerifier.create(tokenString, IDToken.class);

        idTokenTokenVerifier.withChecks(
                new TokenVerifier.RealmUrlCheck(Urls.realmIssuer(authenticationFlowContext.getSession().getContext().getUri().getBaseUri(), authenticationFlowContext.getRealm().getName())),
                TokenVerifier.SUBJECT_EXISTS_CHECK,
                new TokenVerifier.TokenTypeCheck("ID"),
                TokenVerifier.IS_ACTIVE
        );

        PublicKey pk = getPublicKey(idTokenTokenVerifier, authenticationFlowContext);
        idTokenTokenVerifier.publicKey(pk);

        return idTokenTokenVerifier;
    }

    private PublicKey getPublicKey(TokenVerifier<IDToken> idTokenTokenVerifier, AuthenticationFlowContext authenticationFlowContext) throws VerificationException {
        String kid = idTokenTokenVerifier.getHeader().getKeyId();
        KeyWrapper key = authenticationFlowContext.getSession().keys().getKey(
                authenticationFlowContext.getRealm(),
                kid,
                KeyUse.SIG,
                idTokenTokenVerifier.getHeader().getRawAlgorithm()
        );
        return (PublicKey) key.getPublicKey();
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
