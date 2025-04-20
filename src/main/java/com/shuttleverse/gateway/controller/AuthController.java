package com.shuttleverse.gateway.controller;

import java.net.URI;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

  @GetMapping("/login")
  public Mono<Void> login(ServerWebExchange exchange) {
    return Mono.fromRunnable(() -> {
      ServerHttpResponse response = exchange.getResponse();
      response.setStatusCode(HttpStatus.FOUND);
      response.getHeaders().setLocation(URI.create("/oauth2/authorization/google"));
    });
  }

  @GetMapping("/user")
  public Mono<Map<String, Object>> getUserInfo(ServerWebExchange exchange) {
    return exchange.getPrincipal()
        .filter(principal -> principal instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .map(token -> {
          if (token.getPrincipal() instanceof OidcUser oidcUser) {
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("id", oidcUser.getSubject());
            userInfo.put("email", oidcUser.getEmail());
            userInfo.put("name", oidcUser.getFullName());
            return userInfo;
          }
          return Collections.<String, Object>emptyMap();
        })
        .switchIfEmpty(Mono.just(Collections.emptyMap()));
  }
}
