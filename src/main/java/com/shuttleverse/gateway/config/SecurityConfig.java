package com.shuttleverse.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/actuator/**", "/fallback/**").permitAll()
            .pathMatchers("/auth/login", "/oauth2/**").permitAll()
            .anyExchange().authenticated()
        )
        .oauth2Login(oauth2 -> oauth2
            .authenticationFailureHandler((exchange, exception) ->
                Mono.fromRunnable(() -> exchange.getExchange().getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED)))
        )
        .oauth2Client(Customizer.withDefaults())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint((exchange, exception) ->
                Mono.fromRunnable(
                    () -> exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED)))
        )
        .securityContextRepository(new WebSessionServerSecurityContextRepository())
        .logout(logout -> logout
            .logoutUrl("/auth/logout")
            .logoutSuccessHandler((exchange, authentication) -> {
              exchange.getExchange().getResponse().setStatusCode(HttpStatus.OK);
              return Mono.empty();
            }));

    return http.build();
  }
}