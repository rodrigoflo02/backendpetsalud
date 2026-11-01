package com.petsalud.backendpetsalud.service;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mock;

class UsuarioServiceImplTest {

    @Test
    void registrationHashesPasswordAndAlwaysAssignsClientRole() {
        UsuarioRepository repository = mock(UsuarioRepository.class);
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        UsuarioServiceImpl service = new UsuarioServiceImpl(repository, passwordEncoder);
        Usuario request = Usuario.builder()
                .email("cliente@petsalud.cl")
                .password("ClaveSegura123")
                .rol(Rol.GERENTE)
                .build();
        when(repository.findByEmail(request.getEmail())).thenReturn(Optional.empty());
        when(repository.save(any(Usuario.class))).thenAnswer(invocation -> invocation.getArgument(0));

        Usuario saved = service.registrarUsuario(request);

        assertNotEquals("ClaveSegura123", saved.getPassword());
        assertTrue(passwordEncoder.matches("ClaveSegura123", saved.getPassword()));
        assertEquals(Rol.CLIENTE, saved.getRol());
    }
}
