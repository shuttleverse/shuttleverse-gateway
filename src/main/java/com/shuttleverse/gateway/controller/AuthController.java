package com.shuttleverse.gateway.controller;

import com.shuttleverse.gateway.service.ProfileService;
import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final ProfileService profileService;

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
              response.getHeaders()
                  .setLocation(URI.create(profileService.getClientUrl() + "/onboarding"));
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

  @GetMapping("/mock-login")
  public Mono<Void> mockLogin(ServerWebExchange exchange) {
    if (profileService.isProduction()) {
      ServerHttpResponse response = exchange.getResponse();
      response.setStatusCode(HttpStatus.BAD_REQUEST);
      response.getHeaders().setLocation(URI.create("/"));
      return Mono.empty();
    }

    return exchange.getSession().flatMap(session -> {
      Instant now = Instant.now();
      Authentication auth = getAuthentication(now);
      SecurityContext context = new SecurityContextImpl(auth);

      session.getAttributes().put("SPRING_SECURITY_CONTEXT", context);

      ServerHttpResponse response = exchange.getResponse();
      response.setStatusCode(HttpStatus.FOUND);
      response.getHeaders().setLocation(URI.create("/api/community/v1/user/me"));
      return Mono.empty();
    });
  }

  private Authentication getAuthentication(Instant now) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", "userId");
    claims.put("email", "email");
    claims.put("name", "name");

    OidcIdToken idToken = new OidcIdToken(
        "mock-token-value", now, now.plusSeconds(3600), claims);

    List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("USER"));
    OidcUser oidcUser = new DefaultOidcUser(authorities, idToken, "sub");

    return new UsernamePasswordAuthenticationToken(oidcUser, null, authorities);
  }
}
