package com.shuttleverse.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver) {
    http
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .authorizeExchange(exchanges -> exchanges
            .pathMatchers("/actuator/**", "/fallback/**").permitAll()
            .pathMatchers("/login", "/oauth2/**").permitAll()
            .anyExchange().authenticated()
        )
        .oauth2Login(oauth2 -> oauth2
            .authorizedClientRepository(authorizedClientRepository())
            .authorizationRequestResolver(authorizationRequestResolver)
        )
        .oauth2Client(Customizer.withDefaults())
        // Store the security context in the web session
        .securityContextRepository(new WebSessionServerSecurityContextRepository());

    return http.build();
  }

  @Bean
  public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {

    DefaultServerOAuth2AuthorizationRequestResolver resolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(
            clientRegistrationRepository);

    resolver.setAuthorizationRequestCustomizer(builder -> {
      builder.additionalParameters(params -> {
        params.put("access_type", "offline");
        params.put("prompt", "consent");
      });
    });

    return resolver;
  }

  @Bean
  public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }

  @Bean
  public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

    ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
        ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken()
            .build();

    DefaultReactiveOAuth2AuthorizedClientManager manager =
        new DefaultReactiveOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);

    manager.setAuthorizedClientProvider(authorizedClientProvider);

    return manager;
  }
}