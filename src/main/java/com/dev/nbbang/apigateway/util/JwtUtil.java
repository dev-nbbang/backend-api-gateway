package com.dev.nbbang.apigateway.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    public Map<String, Object> getUserParseInfo(String token) {
        Map<String, Object> result = new HashMap<>();
        //expiration date < now
        boolean isExpired = !isTokenExpired(token);
        result.put("memberId", extractAllClaims(token).get("memberId", String.class));
        result.put("isExpired", isExpired);
        System.out.println("parseinfo in getuseroarseinfo: " + result);
        return result;
    }

//    public boolean isValidate(String token) {
//        try {
//            Map<String, Object> info = getUserParseInfo(token);
//        } catch (NullPointerException e) {
//            return false;
//        }
//        // token is expired
//        catch (ExpiredJwtException e) {
//            return false;
//        }
//        // signature is wrong
//        catch (SignatureException e) {
//            return false;
//        }
//        // format is wrong
//        catch (MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
//            return false;
//        }
//        return true;
//    }



    private Key getSigningKey(String secretKey) {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }


    /*
    JWT Payload에 담는 정보의 한 '조각'을 Claim이라 한다.
    Jwt Parser를 빌드하고 Parser에 토큰 넣어서 payload(body) 부분 발췌
     */
    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey(SECRET_KEY))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // 토큰이 만료되었는지 확인
    public Boolean isTokenExpired(String token) {
        Date expiration = extractAllClaims(token).getExpiration();
        return expiration.before(new Date());
    }

}
