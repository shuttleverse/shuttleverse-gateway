package com.shuttleverse.gateway.controller;

import java.net.URI;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  @GetMapping("/login")
  public Mono<Void> login(ServerWebExchange exchange) {
    return exchange.getSession()
        .flatMap(session -> {
          Map<String, Object> attributes = session.getAttributes();

          if (attributes.containsKey("SPRING_SECURITY_CONTEXT")) {
            SecurityContext securityContext =
                (SecurityContext) attributes.get("SPRING_SECURITY_CONTEXT");
            Authentication auth = securityContext.getAuthentication();

            if (auth != null && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken)) {
              ServerHttpResponse response = exchange.getResponse();
              response.setStatusCode(HttpStatus.FOUND);
              return Mono.empty();
            }
          }

          ServerHttpResponse response = exchange.getResponse();
          response.setStatusCode(HttpStatus.FOUND);
          response.getHeaders().setLocation(URI.create("/oauth2/authorization/google"));
          return Mono.empty();
        });
  }

  @GetMapping("/status")
  public Mono<Map<String, Boolean>> getUserInfo(ServerWebExchange exchange) {
    return exchange.getSession()
        .map(session -> {
          Map<String, Object> attributes = session.getAttributes();

          if (attributes.containsKey("SPRING_SECURITY_CONTEXT")) {
            SecurityContext securityContext =
                (SecurityContext) attributes.get("SPRING_SECURITY_CONTEXT");
            Authentication auth = securityContext.getAuthentication();

            if (auth != null && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken)) {
              return Map.of("authenticated", true);
            }
          }
          return Map.of("authenticated", false);
        })
        .defaultIfEmpty(Map.of("authenticated", false))
        .onErrorResume(e -> Mono.just(Map.of("authenticated", false)));
  }
}
