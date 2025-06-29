package com.shuttleverse.gateway.controller;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import java.time.Duration;
import javax.net.ssl.SSLException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.HttpProtocol;
import reactor.netty.http.client.HttpClient;

@RestController
@RequestMapping("/test")
public class GoogleApiTestController {

  private final SslContext sslContextBuilder = SslContextBuilder.forClient()
      .trustManager(InsecureTrustManagerFactory.INSTANCE).build();

  private final HttpClient httpClient = HttpClient.create()
      .secure(sslContextSpec -> sslContextSpec.sslContext(sslContextBuilder))
      .protocol(HttpProtocol.HTTP11)
      .wiretap(true)
      .responseTimeout(Duration.ofSeconds(10));

  private final WebClient webClient = WebClient.builder()
      .clientConnector(new ReactorClientHttpConnector(httpClient))
      .baseUrl("https://www.googleapis.com")
      .build();

  public GoogleApiTestController() throws SSLException {

  }

  @GetMapping("/google-token")
  public Mono<ResponseEntity<String>> testGoogleTokenExchange() {
    return webClient.post()
        .uri("/oauth2/v4/token")
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData("code", "invalid_code")
            .with("client_id", "dummy_client_id")
            .with("client_secret", "dummy_secret")
            .with("redirect_uri", "https://api.shuttleverse.co/login/oauth2/code/google")
            .with("grant_type", "authorization_code"))
        .retrieve()
        .bodyToMono(String.class)
        .map(response -> ResponseEntity.ok("Success:\n" + response))
        .timeout(Duration.ofSeconds(10))
        .onErrorResume(e -> Mono.just(
            ResponseEntity.internalServerError().body("Failed: " + e.getMessage())
        ));
  }

  @GetMapping("/any")
  public Mono<String> testAnyEgress() {
    return webClient.get()
        .uri("https://api.github.com")  // replace with any public API
        .retrieve()
        .bodyToMono(String.class)
        .timeout(Duration.ofSeconds(10))  // overall timeout
        .doOnError(err -> System.err.println("Error calling external API: " + err.getMessage()));
  }
}