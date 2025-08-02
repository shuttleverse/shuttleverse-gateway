package com.shuttleverse.gateway.config;

import com.shuttleverse.gateway.service.ProfileService;
import jakarta.ws.rs.HttpMethod;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

  private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);
  private final ProfileService profileService;

  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOrigins(List.of(profileService.getClientUrl()));
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
            .pathMatchers("/test/**").permitAll()
            .pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
            .anyExchange().authenticated())
        .oauth2Login(oauth2 -> oauth2
            .authenticationFailureHandler((exchange, exception) -> Mono.fromRunnable(() -> {
              logger.warn(exception.getMessage());
              exchange.getExchange().getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            }))
            .authenticationSuccessHandler((exchange, authentication) -> {
              ServerHttpResponse response = exchange.getExchange().getResponse();
              response.setStatusCode(HttpStatus.FOUND);
              response.getHeaders()
                  .setLocation(URI.create(profileService.getClientUrl() + "/onboarding"));
              return response.setComplete();
            }))
        .oauth2Client(Customizer.withDefaults())
        .exceptionHandling(exceptions -> exceptions
            .authenticationEntryPoint((exchange, exception) -> {
              exchange.getRequest().getMethod();
              return Mono.fromRunnable(
                  () -> {
                    logger.warn(exception.getMessage());
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                  });
            }))
        .securityContextRepository(new WebSessionServerSecurityContextRepository())
        .logout(logout -> logout
            .logoutUrl("/api/auth/logout")
            .logoutSuccessHandler((exchange, authentication) -> {
              var response = exchange.getExchange().getResponse();

              return exchange.getExchange().getSession()
                  .doOnNext(WebSession::invalidate)
                  .then(Mono.fromRunnable(() -> {
                    response.addCookie(ResponseCookie.from("SHUTTLEVERSE_SESSION", "")
                        .path("/")
                        .httpOnly(true)
                        .maxAge(0)
                        .build());

                    // 3. Redirect to frontend
                    response.setStatusCode(HttpStatus.FOUND);
                    response.getHeaders()
                        .setLocation(URI.create(profileService.getClientUrl() + "/home"));
                  }))
                  .then(response.setComplete());
            }));

    return http.build();
  }
}