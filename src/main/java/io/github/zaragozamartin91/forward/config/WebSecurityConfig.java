package io.github.zaragozamartin91.forward.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class WebSecurityConfig {


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF is disabled
                .csrf().disable()

                /* By default Spring Security disables rendering within an iframe because allowing a webpage to be added to a frame can be a security issue.
                Since H2 console runs within a frame so while Spring security is enabled, frame options has to be disabled explicitly, in order to get the H2 console working.
                Read more here: https://stackoverflow.com/questions/53395200/h2-console-is-not-showing-in-browser */
                .headers().frameOptions().disable()

                // Specify authorisations =======================================================
                .and().authorizeRequests()

                // only users with ADMIN role can run DELETE actions
                .antMatchers(HttpMethod.DELETE).hasRole("ADMIN")
                
                // admin paths only accessible by users with ADMIN role
                .antMatchers("/admin/**").hasAnyRole("ADMIN")

                // h2-console paths only accessible by users with ADMIN role
                .antMatchers("/h2-console/**").hasAnyRole("ADMIN")
                
                // user paths accessible by users with USER and ADMIN roles
                .antMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                
                // login path is accessible by anyone
                .antMatchers("/login/**").permitAll()
                
                // all other requests must just be authenticated
                .anyRequest().authenticated()

                // ==============================================================================
                
                // enabling form login
                .and().formLogin()
                
                // having sessions only if required
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                ;

        return http.build();
    }


}