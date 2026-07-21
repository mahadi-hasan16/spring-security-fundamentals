package com.springSecurity.fundamentals.utility.classes;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtUtility {
    private final String privateKey = "A JSON Web Token is an open standard used to securely transmit information between parties as a JSON object";

    public String generateJwtToken(String username, String password) {
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        long expMillis = nowMillis + 60000;
        Date exp = new Date(nowMillis + expMillis);

        Map<String, Object> claims = new HashMap<>();
        String jwtKey = Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(now)
                .expiration(exp)
                .and()
                .signWith(getKey())
                .compact();
        return jwtKey;
    }

    private Key getKey() {
        return Keys.hmacShaKeyFor(privateKey.getBytes(StandardCharsets.UTF_8));
    }
}

