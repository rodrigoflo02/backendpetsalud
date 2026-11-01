package com.petsalud.backendpetsalud.security.jwt;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.petsalud.backendpetsalud.security.UsuarioDetailsService;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UsuarioDetailsService usuarioDetailsService;

    //constructor
    public JwtAuthenticationFilter(JwtUtil jwtUtil, UsuarioDetailsService usuarioDetailsService) {
        this.jwtUtil = jwtUtil;
        this.usuarioDetailsService = usuarioDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        //busca el token JWT en la cabecera Authorization de la solicitud HTTP. Si no está presente o no comienza con "Bearer ", continúa con el siguiente filtro
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.substring(7).trim(); //extrae el token
        //Quita el prefijo Bearer  y obtiene el JWT. Si queda vacío, responde 401 y detiene la solicitud:
        if (token.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token JWT inválido");
            return;
        }

        try {
            //obtiene el email
            String username = jwtUtil.extractUsername(token);
            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                //busca los datos del usuario
                UserDetails userDetails = usuarioDetailsService.loadUserByUsername(username);
                //comprueba el token y si es válido, crea un objeto de autenticación y lo establece en el contexto de seguridad de Spring.
                // permite que la solicitud continúe con la información del usuario autenticado. 
                if (!jwtUtil.isTokenValid(token, userDetails)) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token JWT inválido o expirado");
                    return;
                }

                //si es valido crea un objeto de autenticación y lo establece en el contexto de seguridad de Spring.
                var authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(
                        new org.springframework.security.web.authentication.WebAuthenticationDetailsSource()
                                .buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (JwtException | IllegalArgumentException | UsernameNotFoundException exception) {
            SecurityContextHolder.clearContext();
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token JWT inválido o expirado");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
