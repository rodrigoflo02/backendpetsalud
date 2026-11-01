package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.security.config.SecurityConfig;
import com.petsalud.backendpetsalud.security.jwt.JwtAuthenticationFilter;
import com.petsalud.backendpetsalud.security.jwt.JwtUtil;
import com.petsalud.backendpetsalud.service.UsuarioService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.User;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(controllers = com.petsalud.backendpetsalud.controller.UsuarioController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class, JwtUtil.class})
@TestPropertySource(properties =
        "app.jwt.secret=cGV0c2FsdWQtdGVzdC1zZWNyZXQta2V5LWF0LWxlYXN0LTMyLWJ5dGVz")
class RoleAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @MockBean
    private UsuarioService usuarioService;

    @MockBean
    private UsuarioDetailsService usuarioDetailsService;

    @Test
    void protectedEndpointRejectsRequestsWithoutToken() throws Exception {
        mockMvc.perform(get("/api/usuarios"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void clientCannotAccessUserAdministration() throws Exception {
        var client = User.withUsername("cliente@petsalud.cl")
                .password("not-used")
                .authorities("ROLE_CLIENTE")
                .build();
        when(usuarioDetailsService.loadUserByUsername(client.getUsername())).thenReturn(client);

        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + jwtUtil.generateToken(client)))
                .andExpect(status().isForbidden());
    }

    @Test
    void managerCanAccessUserAdministration() throws Exception {
        var manager = User.withUsername("gerente@petsalud.cl")
                .password("not-used")
                .authorities("ROLE_GERENTE")
                .build();
        when(usuarioDetailsService.loadUserByUsername(manager.getUsername())).thenReturn(manager);
        when(usuarioService.listarUsuarios()).thenReturn(List.of());

        mockMvc.perform(get("/api/usuarios")
                        .header("Authorization", "Bearer " + jwtUtil.generateToken(manager)))
                .andExpect(status().isOk());
    }
}
