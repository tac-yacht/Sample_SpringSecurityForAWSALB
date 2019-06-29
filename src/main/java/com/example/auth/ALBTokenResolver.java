package com.example.auth;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;

/**
 * This resolve header by ALB into virtual Bearer token.
 * @see org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver
 */
@Component
public class ALBTokenResolver implements BearerTokenResolver {

	/**
	 * @see <a href="https://docs.aws.amazon.com/ja_jp/elasticloadbalancing/latest/application/listener-authenticate-users.html#user-claims-encoding">AWS Document</a>
	 */
	private static final String ELB_HEADER = "x-amzn-oidc-data";

	private static final OAuth2Error FAILED = new OAuth2Error(String.valueOf(
		HttpStatus.UNAUTHORIZED.value()
	));

	@Override
	public String resolve(HttpServletRequest request) {
		String oidcData = request.getHeader(ELB_HEADER);
		if(null == oidcData) {
			throw new OAuth2AuthenticationException(FAILED);
		}
		return oidcData;
	}

}
