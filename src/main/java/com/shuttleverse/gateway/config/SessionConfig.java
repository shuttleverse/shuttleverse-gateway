package com.shuttleverse.gateway.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.shuttleverse.gateway.service.ProfileService;
import java.time.Duration;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

@Configuration
@RequiredArgsConstructor
@EnableRedisWebSession()
public class SessionConfig implements BeanClassLoaderAware {

  private final ProfileService profileService;
  private ClassLoader loader;

  @Bean
  public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
    return new GenericJackson2JsonRedisSerializer(objectMapper());
  }

  private ObjectMapper objectMapper() {
    ObjectMapper mapper = new ObjectMapper();
    mapper.registerModules(SecurityJackson2Modules.getModules(this.loader));
    return mapper;
  }

  @Override
  public void setBeanClassLoader(@NonNull ClassLoader classLoader) {
    this.loader = classLoader;
  }

  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    Boolean isProd = profileService.isProduction();
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
    resolver.setCookieName("SHUTTLEVERSE_SESSION");
    resolver.setCookieMaxAge(Duration.ofDays(1));
    resolver.addCookieInitializer(responseCookieBuilder -> responseCookieBuilder
        .path("/")
        .httpOnly(true)
        .secure(isProd)
        .domain(isProd ? ".shuttleverse.co" : "localhost")
        .sameSite("Lax"));
    return resolver;
  }
}