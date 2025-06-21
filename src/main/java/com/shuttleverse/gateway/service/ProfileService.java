package com.shuttleverse.gateway.service;

import lombok.RequiredArgsConstructor;
import org.apache.commons.lang.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ProfileService {

  private final Environment environment;

  public Boolean isProduction() {
    return StringUtils.equals(environment.getProperty("spring.profiles.active"), "prod");
  }

  public String getClientUrl() {
    return isProduction() ? "https://shuttleverse.co" : "http://localhost:5173";
  }
}
