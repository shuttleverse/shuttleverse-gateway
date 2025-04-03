package com.shuttleverse.gateway.filter;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {

  private final ReactiveOAuth2AuthorizedClientService authorizedClientService;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    return exchange.getPrincipal()
        .filter(principal -> principal instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .flatMap(this::getAccessToken)
        .map(token -> withBearerAuth(exchange, token))
        .defaultIfEmpty(exchange)
        .flatMap(chain::filter);
  }

  private Mono<String> getAccessToken(OAuth2AuthenticationToken oauthToken) {
    String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
    String principalName = oauthToken.getName();

    log.debug("Getting access token for client registration ID: {} and principal: {}",
        clientRegistrationId, principalName);

    return authorizedClientService
        .loadAuthorizedClient(clientRegistrationId, principalName)
        .map(OAuth2AuthorizedClient::getAccessToken)
        .map(AbstractOAuth2Token::getTokenValue)
        .doOnSuccess(token -> log.debug("Successfully retrieved access token"))
        .doOnError(error -> log.error("Error retrieving access token", error));
  }

  private ServerWebExchange withBearerAuth(ServerWebExchange exchange, String token) {
    return exchange.mutate()
        .request(
            r -> r.headers(headers -> headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token)))
        .build();
  }

  @Override
  public int getOrder() {
    return -1;
  }
}