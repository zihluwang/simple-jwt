package cn.vorbote.simplejwt;

import cn.vorbote.common.utils.MapUtil;
import cn.vorbote.commons.enums.TimeUnit;
import cn.vorbote.time.DateTime;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * JWT Token implementation, easy to use.
 *
 * @author vorbote thills@vorbote.cn
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

    protected String getSecret() {
        return secret;
    }

    protected void setSecret(String secret) {
        this.secret = secret;
    }

    protected String getIssuer() {
        return issuer;
    }

    protected void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Create a new Token
     *
     * @param expireAfter Specify when will the token be expired. (Unit: Second)
     * @param subject     Specify the users will be faced.
     * @param audience    Specify who will receive this token.
     * @param claims      Give some info need to be transformed by token, can be null when
     *                    you don't need to pass any information.
     * @return A token string.
     */
    public String CreateToken(int expireAfter, String subject, String audience, Map<String, Object> claims) {
        var expire = DateTime.Now();
        expire.AddSeconds(expireAfter);

        final var builder = JWT.create();
        if (claims != null) {
            for (Map.Entry<String, Object> e : claims.entrySet()) {
                builder.withClaim(e.getKey(), e.getValue().toString());
            }
        }

        var now = DateTime.Now();

        builder.withIssuer(issuer);
        builder.withIssuedAt(now.ToDate());
        builder.withNotBefore(now.ToDate());
        builder.withAudience(audience);
        builder.withSubject(subject);
        builder.withExpiresAt(expire.ToDate());
        builder.withJWTId(UUID.randomUUID().toString());

        return builder.sign(Algorithm.HMAC512(secret));
    }

    /**
     * Create a new Token by the specified bean object.
     *
     * @param expireAfter Specify when will the token be expired. (Unit: Second)
     * @param subject     Specify the users will be faced.
     * @param audience    Specify who will receive this token.
     * @param bean        Give some info need to be transformed by token, can be null when
     *                    you don't need to pass any information.
     * @return A token string.
     */
    public <T> String CreateTokenWithUserInstance(int expireAfter, String subject, String audience, T bean)
            throws Exception {
        var dict = MapUtil.SetMap(bean);
        return CreateToken(expireAfter, subject, audience, dict);
    }

    /**
     * Check whether the token is valid. This method will happen
     * nothing when the token is valid, or throw some exception
     * when token is invalid.
     *
     * @param token The token.
     */
    public void Verify(String token) {
        JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
    }

    /**
     * Decode the token, and you can easily get some info from
     * this token.
     *
     * @param token The token.
     * @return The decoded jwt token.
     */
    public DecodedJWT Info(String token) {
        return JWT.require(Algorithm.HMAC512(secret)).build().verify(token);
    }

    /**
     * Renew the token.
     *
     * @param token The original token.
     * @return The renewed token.
     */
    public String Renew(String token) {
        final var info = this.Info(token);
        final var map = new HashMap<String, Object>();
        // Exclude some specific keys.
        var keys = Arrays.asList("aud", "sub", "nbf", "iss", "exp", "iat", "jti");
        for (var e : info.getClaims().entrySet()) {
            if (!keys.contains(e.getKey())) {
                map.put(e.getKey(), e.getValue().asString());
            }
        }
        return CreateToken(30 * TimeUnit.MINUTE.Second(),
                info.getSubject(), info.getAudience().get(0), map);
    }

    /**
     * Get the bean in the token. In this method, you have to
     * make sure that your stored info is in the format of
     * key-value pair and which is stored in the claims. And
     * the key must be the same with that field in the required
     * type (such as the field name in required is declared as
     * {@code private String name;}, then your key must be
     * {@code name}). Meanwhile, the setter for this field is
     * required either.
     *
     * @param token        The user token.
     * @param requiredType The class of user.
     * @return The user bean.
     * @throws Exception All exceptions will be generated in this method.
     */
    public <T> T GetBean(String token, Class<T> requiredType)
            throws Exception {
        // 创建token的解析对象
        var tokenInfo = Info(token).getClaims();

        // 获取默认无参构造并创建对象
        var bean = requiredType.getConstructor().newInstance();

        var fields = requiredType.getDeclaredFields();
        for (var field : fields) {
            var fieldName = field.getName();
            // 根据名字创建属性并设置值
            var fieldValue = tokenInfo.get(fieldName).asString();
            MapUtil.SetFieldValue(fieldName, bean, fieldValue);
        }

        return bean;
    }
}
