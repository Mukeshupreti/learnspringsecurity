package com.example.learnspringsecuirty.config.basic;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

//@Configuration
public class BasicAuthSecurityConfiguration {

    @Bean
    SecurityFilterChain basicSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // if you disable csrf then you can call post method without csrf token.
         http.csrf(csrf->csrf.disable());
        // http.formLogin(withDefaults()); /// this will show login form. disable it if you want InMemoryUserDetailsManager
        http.httpBasic(withDefaults());

        //enabling frames for h2 console
        http.headers(headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));

        return http.build();
    }
    // Implementation #1 : InMemoryUserDetailsManager
    // comment spring.security crendials  in application property and disable http.formLogin(withDefaults());

  /*  @Bean
    public UserDetailsService userDetailsService() {
        var admin = User.withUsername("mukesh")
                .password("{noop}upreti")
                .roles("USER")
                .build();
// remember when you put password you have to put upreti not {noop}upreti
        // {noop} => is requried to put else spring security will give you error no encoded password

        var user = User.withUsername("admin")
                .password("{noop}upreti")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }*/

    // implementation 2 : JDBC with h2 to store credential
    @Bean
    public UserDetailsService userDetailService(DataSource dataSource) {
        var user = User.withUsername("mukesh")
               // .password("{noop}upreti")
                .password(passwordEncoder().encode("upreti"))
                .roles("USER")
                .build();
        var admin = User.withUsername("admin")
                // .password("{noop}upreti")
                .password(passwordEncoder().encode("upreti"))
                .roles("ADMIN")
                .build();
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        return jdbcUserDetailsManager;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {

        return new BCryptPasswordEncoder();
    }

    @Bean
    public DataSource dataSource() {
        return new EmbeddedDatabaseBuilder()
                .setType(EmbeddedDatabaseType.H2)
                .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
                .build();
    }
}


