package com.petsalud.backendpetsalud.dto;

import com.petsalud.backendpetsalud.entity.Rol;

public record RegistroResponse(Long id, String email, Rol rol) {
}
