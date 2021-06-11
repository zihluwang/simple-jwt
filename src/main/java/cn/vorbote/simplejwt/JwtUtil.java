package cn.vorbote.simplejwt;

import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * You can use this util to create a simple {@code JSON Web Token}.
 *
 * @author vorbote thills@vorbote.cn
 */
@Slf4j
public final class JwtUtil extends AccessKeyUtil {

    /*
        iss: jwt签发者
        sub: jwt所面向的用户
        aud: 接收jwt的一方
        exp: jwt的过期时间，这个过期时间必须要大于签发时间
        nbf: 定义在什么时间之前，该jwt都是不可用的.
        iat: jwt的签发时间
        jti: jwt的唯一身份标识，主要用来作为一次性token，从而回避重放攻击。
    */

    /**
     * Create a jwt util instance with your unique secret and the issuer.
     *
     * @param secret The secret value.
     * @param issuer Your (organization's) name.
     */
    public JwtUtil(String secret, String issuer) {
        super(secret, issuer);
    }

    protected String getSecret() {
        return super.getSecret();
    }

    protected void setSecret(String secret) {
        super.setSecret(secret);
    }

    protected String getIssuer() {
        return super.getIssuer();
    }

    protected void setIssuer(String issuer) {
        super.setIssuer(issuer);
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
        return super.CreateToken(expireAfter, subject, audience, claims);
    }

    /**
     * Check whether the token is valid. This method will happens
     * nothing when the token is valid, or throw some exception
     * when token is invalid.
     *
     * @param token The token.
     */
    public void Verify(String token) {
        super.Verify(token);
    }

    /**
     * Decode the token and you can easily get some info from this token.
     *
     * @param token The token.
     * @return The decoded jwt token.
     */
    public DecodedJWT Info(String token) {
        return super.Info(token);
    }

    /**
     * Renew the token.
     *
     * @param token The original token.
     * @return The renewed token.
     */
    public String Renew(String token) {
        return super.Renew(token);
    }

}
