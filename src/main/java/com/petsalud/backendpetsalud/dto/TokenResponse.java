package com.petsalud.backendpetsalud.dto;

public record TokenResponse(String accessToken, String tokenType, long expiresIn) {
}
