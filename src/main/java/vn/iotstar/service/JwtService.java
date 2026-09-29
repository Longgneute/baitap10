package vn.iotstar.service;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import vn.iotstar.config.JwtProperties;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;

@Service
public class JwtService {

	private final JwtProperties jwtProperties;

	public JwtService(JwtProperties jwtProperties) {
		this.jwtProperties = jwtProperties;
	}

	public String generateToken(UserDetails userDetails) {
		Date now = new Date();
		Date expiration = new Date(now.getTime() + jwtProperties.getExpirationTime());

		JWTClaimsSet claims = new JWTClaimsSet.Builder().subject(userDetails.getUsername()).issueTime(now)
				.expirationTime(expiration).build();

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

		try {
			signedJWT.sign(new MACSigner(getSecretKey()));
			return signedJWT.serialize();
		} catch (JOSEException e) {
			throw new IllegalStateException("Không thể tạo JWT", e);
		}
	}

	public String extractUsername(String token) {
		try {
			SignedJWT signedJWT = SignedJWT.parse(token);
			return signedJWT.getJWTClaimsSet().getSubject();
		} catch (ParseException e) {
			throw new IllegalArgumentException("JWT không hợp lệ", e);
		}
	}

	public boolean isTokenValid(String token, UserDetails userDetails) {
		try {
			SignedJWT signedJWT = SignedJWT.parse(token);

			boolean signatureValid = signedJWT.verify(new MACVerifier(getSecretKey()));

			String username = signedJWT.getJWTClaimsSet().getSubject();
			Date expiration = signedJWT.getJWTClaimsSet().getExpirationTime();

			return signatureValid && username != null && username.equals(userDetails.getUsername())
					&& expiration != null && expiration.after(new Date());

		} catch (ParseException | JOSEException e) {
			return false;
		}
	}

	private byte[] getSecretKey() {
		return jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8);
	}
}
