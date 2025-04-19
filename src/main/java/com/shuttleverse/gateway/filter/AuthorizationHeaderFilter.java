package com.shuttleverse.gateway.filter;

import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {

  private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    return exchange.getPrincipal()
        .filter(principal -> principal instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .flatMap(this::getTokens)
        .map(tokens -> withBearerAuth(exchange, tokens.get("idToken")))
        .defaultIfEmpty(exchange)
        .flatMap(chain::filter);
  }

  private Mono<Map<String, String>> getTokens(OAuth2AuthenticationToken oauthToken) {
    String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();

    // Check if ID token can be retrieved directly from the authentication
    if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
      String idToken = oidcUser.getIdToken().getTokenValue();

      Map<String, String> tokens = new HashMap<>();
      tokens.put("idToken", idToken);

      return Mono.just(tokens);
    }

    // Fallback to getting tokens via authorized client manager
    return authorizedClientManager
        .authorize(OAuth2AuthorizeRequest.withClientRegistrationId(clientRegistrationId)
            .principal(oauthToken)
            .build())
        .flatMap(authorizedClient -> {
          Map<String, String> tokens = new HashMap<>();

          // cast to get the ID token
          if (oauthToken.getPrincipal() instanceof OidcUser oidcUser) {
            tokens.put("idToken", oidcUser.getIdToken().getTokenValue());
          }

          return Mono.just(tokens);
        })
        .doOnError(error -> log.error("Error retrieving tokens", error));
  }

  private ServerWebExchange withBearerAuth(ServerWebExchange exchange, String token) {
    return exchange.mutate()
        .request(
            r -> r.headers(headers -> headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token)))
        .build();
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }
}