package cn.vorbote.simplejwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * Another implement of JWT.
 *
 * @author vorbote thills@vorbote.cn
 * @see JwtUtil
 */
public class AccessKeyUtil {
    /*
        iss: jwt签发者
        sub: jwt所面向的用户
        aud: 接收jwt的一方
        exp: jwt的过期时间，这个过期时间必须要大于签发时间
        nbf: 定义在什么时间之前，该jwt都是不可用的.
        iat: jwt的签发时间
        jti: jwt的唯一身份标识，主要用来作为一次性token，从而回避重放攻击。
    */

    private String secret;
    private String issuer;

    /**
     * Create a jwt util instance with your unique secret and the issuer.
     *
     * @param secret The secret value.
     * @param issuer Your (organization's) name.
     */
    public AccessKeyUtil(String secret, String issuer) {
        this.secret = secret;
        this.issuer = issuer;
    }

    private String getSecret() {
        return secret;
    }

    private void setSecret(String secret) {
        this.secret = secret;
    }

    private String getIssuer() {
        return issuer;
    }

    private void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Create a new Token
     * @param expireAfter Specify when will the token be expired. (Unit: Second)
     * @param subject Specify the users will be faced.
     * @param audience Specify who will receive this token.
     * @param claims Give some info need to be transformed by token, can be null when
     *               you dont need to pass any information.
     * @return A token string.
     */
    public String CreateToken(int expireAfter, String subject, String audience, Map<String, Object> claims) {
        var calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, expireAfter); // 设置多少秒后失效

        final var builder = JWT.create();
        if (claims != null) {
            claims.forEach((k, v) -> {
                builder.withClaim(k, v.toString());
            });
        }

        Date now = new Date();

        builder.withIssuer(issuer);
        builder.withIssuedAt(now);
        builder.withNotBefore(now);
        builder.withAudience(audience);
        builder.withSubject(subject);
        builder.withExpiresAt(calendar.getTime());
        builder.withJWTId(UUID.randomUUID().toString());

        return builder.sign(Algorithm.HMAC512(secret));
    }

    /**
     * Check whether the token is valid. This method will happens
     * nothing when the token is valid, or throw some exception
     * when token is invalid.
     *
     * @param token The token.
     */
    public void Verify(String token) {
        JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
    }

    /**
     * Decode the token and you can easily get some info from this token.
     *
     * @param token The token.
     * @return The decoded jwt token.
     */
    public DecodedJWT Info(String token) {
        return JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
    }
}
