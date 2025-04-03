package com.shuttleverse.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  // Configure the session properties through application properties instead
  // No custom WebSessionManager bean is needed as we'll use properties

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/actuator/**", "/fallback/**").permitAll()
            .pathMatchers("/login", "/oauth2/**").permitAll()
            .anyExchange().authenticated()
        )
        .oauth2Login(oauth2 -> {
        })
        .oauth2Client(oauth2 -> {
        })
        // Store the security context in the web session
        .securityContextRepository(new WebSessionServerSecurityContextRepository());

    return http.build();
  }

}