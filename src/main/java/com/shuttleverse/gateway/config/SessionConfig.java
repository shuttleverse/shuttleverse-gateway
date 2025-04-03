package com.shuttleverse.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

@Configuration
public class SessionConfig {

  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
    resolver.setCookieName("GATEWAY_SESSION");
    resolver.setCookieMaxAge(java.time.Duration.ofMinutes(30));
    resolver.addCookieInitializer(responseCookieBuilder ->
        responseCookieBuilder
            .path("/")
            .httpOnly(true)
            .secure(true)
            .sameSite("Lax")
    );
    return resolver;
  }
}