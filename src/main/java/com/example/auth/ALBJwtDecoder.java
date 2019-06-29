package com.example.auth;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.JwsAlgorithms;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.MappedJwtClaimSetConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoderJwkSupport;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * origin by {@link NimbusJwtDecoderJwkSupport}.
 * This is only replace "{@link JWSKeySelector}"
 * @see NimbusJwtDecoderJwkSupport
 */
@Component
public class ALBJwtDecoder implements JwtDecoder {

	private static final String DECODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to decode the Jwt: %s";

	private final JWSAlgorithm jwsAlgorithm;
	private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
	private final RestOperationsResourceRetriever jwkSetRetriever = new RestOperationsResourceRetriever();

	private Converter<Map<String, Object>, Map<String, Object>> claimSetConverter =
			MappedJwtClaimSetConverter.withDefaults(Collections.emptyMap());
	private OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefault();


	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 */
	@Autowired
	public ALBJwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUrl) {
		this(jwkSetUrl, JwsAlgorithms.ES256);
	}

	/**
	 * Constructs a {@code NimbusJwtDecoderJwkSupport} using the provided parameters.
	 *
	 * @param jwkSetUrl the JSON Web Key (JWK) Set {@code URL}
	 * @param jwsAlgorithm the JSON Web Algorithm (JWA) used for verifying the digital signatures
	 */
	private ALBJwtDecoder(String jwkSetUrl, String jwsAlgorithm) {
		Assert.hasText(jwkSetUrl, "jwkSetUrl cannot be empty");
		Assert.hasText(jwsAlgorithm, "jwsAlgorithm cannot be empty");
		JWKSource jwkSource;
		try {
			jwkSource = new RemoteJWKSet(new URL(jwkSetUrl), this.jwkSetRetriever);
		} catch (MalformedURLException ex) {
			throw new IllegalArgumentException("Invalid JWK Set URL \"" + jwkSetUrl + "\" : " + ex.getMessage(), ex);
		}
		this.jwsAlgorithm = JWSAlgorithm.parse(jwsAlgorithm);
		JWSKeySelector<SecurityContext> jwsKeySelector =
			new ALBPublicKeySelector<SecurityContext>(this.jwsAlgorithm, jwkSource);
		this.jwtProcessor = new DefaultJWTProcessor<>();
		this.jwtProcessor.setJWSKeySelector(jwsKeySelector);

		// Spring Security validates the claim set independent from Nimbus
		this.jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {});
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		JWT jwt = this.parse(token);
		if (jwt instanceof SignedJWT) {
			Jwt createdJwt = this.createJwt(token, jwt);
			return this.validateJwt(createdJwt);
		}
		throw new JwtException("Unsupported algorithm of " + jwt.getHeader().getAlgorithm());
	}

	/**
	 * Use this {@link Jwt} Validator
	 *
	 * @param jwtValidator - the Jwt Validator to use
	 */
	public void setJwtValidator(OAuth2TokenValidator<Jwt> jwtValidator) {
		Assert.notNull(jwtValidator, "jwtValidator cannot be null");
		this.jwtValidator = jwtValidator;
	}

	/**
	 * Use the following {@link Converter} for manipulating the JWT's claim set
	 *
	 * @param claimSetConverter the {@link Converter} to use
	 */
	public final void setClaimSetConverter(Converter<Map<String, Object>, Map<String, Object>> claimSetConverter) {
		Assert.notNull(claimSetConverter, "claimSetConverter cannot be null");
		this.claimSetConverter = claimSetConverter;
	}

	private JWT parse(String token) {
		try {
			return JWTParser.parse(token);
		} catch (Exception ex) {
			throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

	private Jwt createJwt(String token, JWT parsedJwt) {
		Jwt jwt;

		try {
			// Verify the signature
			JWTClaimsSet jwtClaimsSet = this.jwtProcessor.process(parsedJwt, null);

			Map<String, Object> headers = new LinkedHashMap<>(parsedJwt.getHeader().toJSONObject());
			Map<String, Object> claims = this.claimSetConverter.convert(jwtClaimsSet.getClaims());

			Instant expiresAt = (Instant) claims.get(JwtClaimNames.EXP);
			Instant issuedAt = (Instant) claims.get(JwtClaimNames.IAT);
			jwt = new Jwt(token, issuedAt, expiresAt, headers, claims);
		} catch (RemoteKeySourceException ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed Jwk set"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		} catch (Exception ex) {
			if (ex.getCause() instanceof ParseException) {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, "Malformed payload"));
			} else {
				throw new JwtException(String.format(DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
			}
		}

		return jwt;
	}

	private Jwt validateJwt(Jwt jwt){
		OAuth2TokenValidatorResult result = this.jwtValidator.validate(jwt);
		if (result.hasErrors()) {
			String description = result.getErrors().iterator().next().getDescription();
			throw new JwtValidationException(
					String.format(DECODING_ERROR_MESSAGE_TEMPLATE, description),
					result.getErrors());
		}

		return jwt;
	}

	/**
	 * Sets the {@link RestOperations} used when requesting the JSON Web Key (JWK) Set.
	 *
	 * @since 5.1
	 * @param restOperations the {@link RestOperations} used when requesting the JSON Web Key (JWK) Set
	 */
	public final void setRestOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		this.jwkSetRetriever.restOperations = restOperations;
	}

	private static class RestOperationsResourceRetriever implements ResourceRetriever {
		private RestOperations restOperations = new RestTemplate();

		@Override
		public Resource retrieveResource(URL url) throws IOException {
			HttpHeaders headers = new HttpHeaders();
			headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON_UTF8));

			ResponseEntity<String> response;
			try {
				RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET, url.toURI());
				response = this.restOperations.exchange(request, String.class);
			} catch (Exception ex) {
				throw new IOException(ex);
			}

			if (response.getStatusCodeValue() != 200) {
				throw new IOException(response.toString());
			}

			return new Resource(response.getBody(), "UTF-8");
		}
	}
}
