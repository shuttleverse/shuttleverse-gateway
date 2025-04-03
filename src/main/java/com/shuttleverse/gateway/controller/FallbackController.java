package com.shuttleverse.gateway.controller;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Controller that handles fallback responses when services are down or unavailable.
 */
@RestController
@RequestMapping("/fallback")
public class FallbackController {

  @GetMapping("/community-service")
  public Mono<ResponseEntity<Map<String, Object>>> communityServiceFallback() {
    Map<String, Object> response = createFallbackResponse("User Service is currently unavailable");
    return Mono.just(new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE));
  }

  @GetMapping("/aggregator-service")
  public Mono<ResponseEntity<Map<String, Object>>> aggregatorServiceFallback() {
    Map<String, Object> response = createFallbackResponse("Order Service is currently unavailable");
    return Mono.just(new ResponseEntity<>(response, HttpStatus.SERVICE_UNAVAILABLE));
  }

  private Map<String, Object> createFallbackResponse(String message) {
    Map<String, Object> response = new HashMap<>();
    response.put("timestamp", LocalDateTime.now().toString());
    response.put("status", HttpStatus.SERVICE_UNAVAILABLE.value());
    response.put("error", "Service Unavailable");
    response.put("message", message);
    response.put("path", "/fallback");
    return response;
  }
}