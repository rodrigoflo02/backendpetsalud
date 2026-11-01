package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collections;
import java.util.Collection;

public class UsuarioDetails implements UserDetails 
//UserDetails entrega datos como el nombre de usuario, la contraseña, los roles y el estado de la cuenta
// traduce el registro al formato que Spring Security entiende
{

    private final Usuario usuario;

    public UsuarioDetails(Usuario usuario) {
        this.usuario = usuario;
    }

    // convierte el rol guardado en el usuario a una autoridad que Spring puede usar
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        String authority = switch (usuario.getRol()) {
            case VETERINARIO -> "ROLE_EMPLEADO";
            case ADMIN -> "ROLE_GERENTE";
            default -> "ROLE_" + usuario.getRol().name();
        };
        return Collections.singleton(new SimpleGrantedAuthority(authority));
    }

    @Override
    public String getPassword() {
        return usuario.getPassword();
    }

    @Override
    public String getUsername() {
        return usuario.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Puedes implementar lógica adicional si es necesario
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Puedes implementar lógica adicional si es necesario
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Puedes implementar lógica adicional si es necesario
    }

    @Override
    public boolean isEnabled() {
        return true; // Puedes implementar lógica adicional si es necesario
    }
}
