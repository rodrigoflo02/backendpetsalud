package com.petsalud.backendpetsalud.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil { //crear y leer tokens JWT

    private final SecretKey signingKey; //clave con la que firma y verifica los tokens
    private final long expirationMs; //cuánto tiempo dura el token, en milisegundos.
    private final String issuer; //quién emite el token; aquí, por defecto, petsalud-api

    //Constuctor que recibe los valores de configuración desde application.properties
    public JwtUtil(
            @Value("${app.jwt.secret}") String base64Secret,
            @Value("${app.jwt.expiration-ms:900000}") long expirationMs,
            @Value("${app.jwt.issuer:petsalud-api}") String issuer
    ) {
        this.signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64Secret));
        if (expirationMs <= 0) {
            throw new IllegalArgumentException("La duración del JWT debe ser mayor que cero");
        }
        this.expirationMs = expirationMs;
        this.issuer = issuer;
    }

    //Genera un token JWT para un usuario dado, incluyendo su nombre de usuario, roles y fecha de expiración.
    public String generateToken(UserDetails userDetails) {
        Instant issuedAt = Instant.now();
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .issuer(issuer)
                .issuedAt(Date.from(issuedAt))
                //Autoridades de usuario
                .expiration(Date.from(issuedAt.plusMillis(expirationMs)))
                .claim("roles", userDetails.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList())
                //Firma del token con la clave secreta y el algoritmo HS256
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    //extrael el email del token JWT, que se encuentra en el campo "subject" del token.
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    //valida el usuario
    public boolean isTokenValid(String token, UserDetails userDetails) {
        Claims claims = parseClaims(token);
        return claims.getSubject().equals(userDetails.getUsername())
                && claims.getExpiration().after(new Date());
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }

    //verifica la firma del token y extrae los claims (información) del mismo. Si el token no es válido, lanzará una excepción.
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(issuer)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
