package com.shuttleverse.gateway.config;

import jakarta.ws.rs.HttpMethod;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of("http://localhost:5173"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("*"));
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
  }

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http
        .cors(cors -> cors.configurationSource(corsConfigurationSource()))
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/actuator/**", "/fallback/**").permitAll()
            .pathMatchers("/api/auth/login", "/oauth2/**").permitAll()
            .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .anyExchange().authenticated())
        .oauth2Login(oauth2 -> oauth2
            .authenticationFailureHandler((exchange,
                exception) -> Mono.fromRunnable(() -> exchange.getExchange().getResponse()
                    .setStatusCode(HttpStatus.UNAUTHORIZED)))
            .authenticationSuccessHandler((exchange, authentication) -> {
              ServerHttpResponse response = exchange.getExchange().getResponse();
              response.setStatusCode(HttpStatus.FOUND);
              response.getHeaders().setLocation(URI.create("http://localhost:5173/home"));
              return Mono.empty();
            }))
        .oauth2Client(Customizer.withDefaults())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint((exchange, exception) -> {
              exchange.getRequest().getMethod();
              return Mono.fromRunnable(
                  () -> exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED));
            }))
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