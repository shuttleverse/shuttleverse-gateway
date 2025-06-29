package com.shuttleverse.gateway.controller;

import java.time.Duration;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@RestController
@RequestMapping("/test")
public class GoogleApiTestController {

  private final WebClient webClient = WebClient.builder()
      .baseUrl("https://www.googleapis.com")
      .build();

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
}