package com.shuttleverse.gateway.config;

import java.security.Principal;
import java.util.Objects;
import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RateLimiterConfig {

  /**
   * Rate limiting based on user principal name (authenticated user) Falls back to IP address for
   * unauthenticated requests.
   */
  @Bean
  public KeyResolver userKeyResolver() {
    return exchange -> {
      // If user is authenticated, use their username as key
      if (exchange.getPrincipal().blockOptional().isPresent()) {
        return exchange.getPrincipal()
            .map(Principal::getName)
            .cast(String.class);
      }
 
      // Otherwise, use the client's IP address
      String ipAddress = Objects.requireNonNull(exchange.getRequest().getRemoteAddress())
          .getAddress().getHostAddress();
      return Mono.just(ipAddress);
    };
  }
}