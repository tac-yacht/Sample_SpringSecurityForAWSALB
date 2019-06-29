package com.example.auth;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Resource;
import com.nimbusds.jose.util.X509CertUtils;

/**
 * JWTを検証すための鍵を取得する。JWTで定義されているアルゴリズムマッチしない場合取得されない
 */
public class ALBPublicKeySelector<C extends SecurityContext> extends JWSVerificationKeySelector<C> {

	/**
	 * The PEM start marker.
	 */
	private static final String PEM_BEGIN_MARKER = "-----BEGIN PUBLIC KEY-----";


	/**
	 * The PEM end marker.
	 */
	private static final String PEM_END_MARKER = "-----END PUBLIC KEY-----";


	private final RemoteJWKSet<C> jwkset;

	private final String baseURL;

	private static final Logger log = LoggerFactory.getLogger(ALBPublicKeySelector.class);

	public ALBPublicKeySelector(JWSAlgorithm jwsAlg, JWKSource<C> jwkSource) {
		super(jwsAlg, jwkSource);
		assert(RemoteJWKSet.class.isInstance(jwkSource));

		jwkset = ((RemoteJWKSet<C>)jwkSource);
		baseURL = jwkset.getJWKSetURL().toString();
	}

	@Override
	public List<Key> selectJWSKeys(JWSHeader jwsHeader, C context) throws KeySourceException {
		if (! getExpectedJWSAlgorithm().equals(jwsHeader.getAlgorithm())) {
			// Unexpected JWS alg
			return Collections.emptyList();
		}

		String signer = jwsHeader.getCustomParam("signer").toString();
		String kid = jwsHeader.getKeyID();

		log.debug("ALB public key URL:{}", getURL(baseURL + kid));

		Resource rawPublicKey;
		try {
			rawPublicKey = jwkset.getResourceRetriever().retrieveResource(getURL(baseURL + kid));
			//https://docs.aws.amazon.com/ja_jp/elasticloadbalancing/latest/application/listener-authenticate-users.html
		} catch (IOException e) {
			e.printStackTrace();
			return Collections.emptyList();
		}

		return Collections.singletonList(parse(rawPublicKey.getContent()));
	}

	private static final URL getURL(String raw) {
		try {
			return new URL(raw);
		} catch(MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}


	/**
	 * @see X509CertUtils#parse(String)
	 */
	private static ECPublicKey parse(final String pemEncodedCert) {

		if (pemEncodedCert == null || pemEncodedCert.isEmpty()) {
			return null;
		}

		final int markerStart = pemEncodedCert.indexOf(PEM_BEGIN_MARKER);

		if (markerStart < 0) {
			return null;
		}

		String buf = pemEncodedCert.substring(markerStart + PEM_BEGIN_MARKER.length());

		final int markerEnd = buf.indexOf(PEM_END_MARKER);

		if (markerEnd < 0) {
			return null;
		}

		buf = buf.substring(0, markerEnd);

		buf = buf.replaceAll("\\s", "");

		return parse(new Base64(buf).decode());
	}

	/**
	 * @see X509CertUtils#parse(byte[])
	 */
	private static ECPublicKey parse(final byte[] derEncodedCert) {

		if (derEncodedCert == null || derEncodedCert.length == 0) {
			return null;
		}

		final PublicKey key;
		try {
			X509EncodedKeySpec spec = new X509EncodedKeySpec(derEncodedCert);
			KeyFactory kf = KeyFactory.getInstance("EC");
			key = kf.generatePublic(spec);
		} catch (NoSuchAlgorithmException|InvalidKeySpecException e) {
			return null;
		}

		if (! (key instanceof ECPublicKey)) {
			return null;
		}

		return (ECPublicKey)key;
	}


}
