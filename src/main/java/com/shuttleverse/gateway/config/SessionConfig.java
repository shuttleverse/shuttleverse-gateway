package com.shuttleverse.gateway.config;

import com.shuttleverse.gateway.service.ProfileService;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisOperations;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

@Configuration
@RequiredArgsConstructor
@EnableRedisWebSession()
public class SessionConfig {

  private final ProfileService profileService;

  @Bean
  public ReactiveRedisOperations<String, Object> redisOperations(
      ReactiveRedisConnectionFactory factory) {
    Jackson2JsonRedisSerializer<Object> serializer = new Jackson2JsonRedisSerializer<>(
        Object.class);

    RedisSerializationContext.RedisSerializationContextBuilder<String, Object> builder =
        RedisSerializationContext.newSerializationContext(new StringRedisSerializer());

    RedisSerializationContext<String, Object> context = builder
        .value(serializer)
        .hashValue(serializer)
        .build();

    return new ReactiveRedisTemplate<>(factory, context);
  }

  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    Boolean isProd = profileService.isProduction();
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
    resolver.setCookieName("SHUTTLEVERSE_SESSION");
    resolver.setCookieMaxAge(Duration.ofDays(1));
    resolver.addCookieInitializer(responseCookieBuilder ->
        responseCookieBuilder
            .path("/")
            .httpOnly(true)
            .secure(isProd)
            .sameSite(isProd ? "Strict" : "Lax")
    );
    return resolver;
  }
}