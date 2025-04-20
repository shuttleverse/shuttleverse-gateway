package com.shuttleverse.gateway.config;

import java.time.Duration;
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
@EnableRedisWebSession()
public class SessionConfig {

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
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();
    resolver.setCookieName("SHUTTLEVERSE_SESSION");
    resolver.setCookieMaxAge(Duration.ofDays(1));
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