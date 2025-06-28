package com.shuttleverse.gateway.filter;

import java.time.Instant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthorizationHeaderFilter implements GlobalFilter, Ordered {

  private final JwtEncoder jwtEncoder;
  private final JwtDecoder jwtDecoder;
  private final String issuerUrl = "https://shuttleverse.co";

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    log.debug("AuthorizationHeaderFilter processing request: {} {}",
        exchange.getRequest().getMethod(), exchange.getRequest().getURI());

    return exchange.getSession()
        .flatMap(session -> {
          if (session.getAttribute("SPRING_SECURITY_CONTEXT") != null) {
            return getOrCreateInternalToken(session)
                .doOnNext(token -> log.debug("Internal token retrieved/created successfully"))
                .map(token -> withBearerAuth(exchange, token))
                .flatMap(chain::filter);
          }
          return chain.filter(exchange);
        });
  }

  private Mono<String> getOrCreateInternalToken(WebSession session) {
    String existingToken = session.getAttribute("INTERNAL_TOKEN");
    Long expiryTime = session.getAttribute("INTERNAL_TOKEN_EXPIRY");
    Instant now = Instant.now();

    // If token exists and isn't near expiration, reuse it
    if (existingToken != null && expiryTime != null
        && now.plusSeconds(600).isBefore(Instant.ofEpochMilli(expiryTime))) {
      return Mono.just(existingToken);
    }

    log.debug("Creating new internal token");
    return createNewInternalToken(session);
  }

  private Mono<String> createNewInternalToken(WebSession session) {
    SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
    if (securityContext == null || securityContext.getAuthentication() == null) {
      return Mono.empty();
    }

    Authentication auth = securityContext.getAuthentication();
    if (!(auth.getPrincipal() instanceof OidcUser oidcUser)) {
      return Mono.empty();
    }

    String userId = oidcUser.getSubject();

    Instant now = Instant.now();
    Instant expiry = now.plusSeconds(3600);

    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer(this.issuerUrl)
        .subject(userId)
        .issuedAt(now)
        .expiresAt(expiry)
        .claim("s_id", session.getId())
        .claim("email", oidcUser.getEmail())
        .claim("name", oidcUser.getFullName())
        .build();

    JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
    String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

    // Store in session
    session.getAttributes().put("INTERNAL_TOKEN", token);
    session.getAttributes().put("INTERNAL_TOKEN_EXPIRY", expiry.toEpochMilli());

    log.debug("Internal token created and stored in session - Token length: {}, Expires at: {}",
        token.length(), expiry);

    return Mono.just(token);
  }

  private boolean isTokenValid(String token) {
    try {
      Jwt jwt = jwtDecoder.decode(token);

      Instant expiration = jwt.getExpiresAt();
      if (expiration != null && expiration.isBefore(Instant.now())) {
        return false;
      }

      String issuer = jwt.getIssuer().toString();
      return this.issuerUrl.equals(issuer);
    } catch (Exception e) {
      return false;
    }
  }

  private ServerWebExchange withBearerAuth(ServerWebExchange exchange, String token) {
    if (!isTokenValid(token)) {
      return exchange;
    }

    return exchange.mutate()
        .request(r -> r.headers(headers -> {
          headers.remove(HttpHeaders.AUTHORIZATION);
          headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }))
        .build();
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 10;
  }
}