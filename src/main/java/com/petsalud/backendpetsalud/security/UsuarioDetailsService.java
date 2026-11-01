package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.repository.UsuarioRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
//busca el registro del usuario en la base de datos.
public class UsuarioDetailsService implements UserDetailsService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Override
    //loadUserByUsername recibe el email, busca al usuario en la base de datos mediante UsuarioRepository y, si lo encuentra, lo envuelve en un UsuarioDetails.
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado con email: " + email));
        return new UsuarioDetails(usuario);
    }
}

/*
email recibido
→ buscar Usuario en la base de datos
→ convertirlo a UsuarioDetails
→ Spring obtiene contraseña y rol
*/
