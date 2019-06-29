package com.example;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class Controller {

	private static final Logger log = LoggerFactory.getLogger(Controller.class);

	@GetMapping(path="/", produces = MediaType.APPLICATION_JSON_VALUE)
	public Object Header(@RequestHeader MultiValueMap<String, String> headers) {
		return headers;
	}

	@GetMapping("/hello")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		log.debug(jwt.getTokenValue());
		return String.format("Hello, %s!", jwt.getSubject());
	}
}
