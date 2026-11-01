package com.petsalud.backendpetsalud.security.config;

import javax.swing.Spring;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.petsalud.backendpetsalud.security.jwt.JwtAuthenticationFilter;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain( //conjunto de reglas y filtros que aplicará Spring.
            HttpSecurity http, //permite configurar la seguridad web
            JwtAuthenticationFilter jwtAuthenticationFilter //filtro que revisa el token
    ) throws Exception {
        return http
        
                .csrf(AbstractHttpConfigurer::disable) //desactiva la protección CSRF
                .httpBasic(AbstractHttpConfigurer::disable) //desactiva la autenticación HTTP Basic.
                .formLogin(AbstractHttpConfigurer::disable) //desactiva la pantalla de login predeterminada de Spring.
                .logout(AbstractHttpConfigurer::disable) //desactiva el cierre de sesión predeterminado.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) //Spring no mantendrá una sesión de usuario entre solicitudes.
                
                //Si no tiene autenticación, devuelve un error 401 (no autorizado) con el mensaje "Autenticación requerida".
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) ->
                                response.sendError(401, "Autenticación requerida")))
                .authorizeHttpRequests(authorize -> authorize

                        //Se define rutas publicas y privadas, y los roles necesarios para acceder a ellas.

                        .requestMatchers(HttpMethod.POST, "/api/usuarios/registro", "/api/auth/login").permitAll()
                        //La consulta de productos con stock bajo requiere que el usuario tenga rol de empleado o gerente
                        .requestMatchers(HttpMethod.GET, "/api/productos/stock-bajo")
                        .hasAnyRole("EMPLEADO", "GERENTE")
                        //consultar productos sin autenticarse.
                        .requestMatchers(HttpMethod.GET, "/api/productos", "/api/productos/{id}",
                                "/api/productos/categoria").permitAll()
                        //El resto de las rutas bajo /api/usuarios/ requiere rol gerente
                        .requestMatchers("/api/usuarios/**").hasRole("GERENTE")
                        //Cualquier otra ruta /api/... requiere empleado o gerente.
                        .requestMatchers("/api/**").hasAnyRole("EMPLEADO", "GERENTE")
                        .anyRequest().denyAll())

                //filtro JWT antes del filtro de autenticación estándar por usuario y contraseña.
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    //coordina la autenticación cuando el usuario inicia sesión
    @Bean
    public AuthenticationManager authenticationManager(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        //se encarga de validar la autenticacion de los usuarios contra la base de datos

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return new ProviderManager(provider);
    }

    //Hash de contraseñas para almacenarlas de forma segura en la base de datos. Protege contra ataques de diccionario y fuerza bruta.
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
