package com.petsalud.backendpetsalud.security;

import io.jsonwebtoken.JwtException;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;

import com.petsalud.backendpetsalud.security.jwt.JwtUtil;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilTest {

    private static final String SECRET = Base64.getEncoder().encodeToString(
            "petsalud-test-secret-key-at-least-32-bytes".getBytes());

    @Test
    void generatedTokenContainsSubjectAndValidSignature() {
        JwtUtil jwtUtil = new JwtUtil(SECRET, 900_000, "petsalud-api");
        var user = User.withUsername("cliente@petsalud.cl")
                .password("not-used")
                .authorities("ROLE_CLIENTE")
                .build();

        String token = jwtUtil.generateToken(user);

        assertEquals("cliente@petsalud.cl", jwtUtil.extractUsername(token));
        assertTrue(jwtUtil.isTokenValid(token, user));
    }

    @Test
    void rejectsTokensSignedWithAnotherKey() {
        JwtUtil issuer = new JwtUtil(SECRET, 900_000, "petsalud-api");
        JwtUtil verifier = new JwtUtil(Base64.getEncoder().encodeToString(
                "another-test-secret-key-at-least-32-bytes".getBytes()), 900_000, "petsalud-api");
        var user = User.withUsername("cliente@petsalud.cl")
                .password("not-used")
                .authorities("ROLE_CLIENTE")
                .build();

        assertThrows(JwtException.class, () -> verifier.extractUsername(issuer.generateToken(user)));
    }

    @Test
    void rejectsTokensForAnotherIssuer() {
        JwtUtil issuer = new JwtUtil(SECRET, 900_000, "untrusted-issuer");
        JwtUtil verifier = new JwtUtil(SECRET, 900_000, "petsalud-api");
        var user = User.withUsername("cliente@petsalud.cl")
                .password("not-used")
                .authorities("ROLE_CLIENTE")
                .build();

        assertThrows(JwtException.class, () -> verifier.extractUsername(issuer.generateToken(user)));
    }
}
