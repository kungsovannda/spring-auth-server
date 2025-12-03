package co.istad.springauthserver.feature.client.dto;

import java.util.Set;

public record ClientRequest(
        String clientId,
        String clientSecret,
        String clientName,
        Set<String> redirectUris,
        Set<String> postLogoutRedirectUris,
        Set<String> grantTypes, // e.g., "authorization_code", "refresh_token", "client_credentials"
        Set<String> scopes,
        Boolean requireAuthorizationConsent,
        Boolean requireProofKey,
        Long accessTokenTimeToLive,
        Long refreshTokenTimeToLive,
        Boolean isReuseRefreshToken
) {
}
