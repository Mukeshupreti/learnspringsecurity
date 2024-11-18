package com.example.learnspringsecuirty.config.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class BasicAuthSecurityConfiguration {





//  @Bean
//  SecurityFilterChain basicSecurityFilterChain(HttpSecurity http) throws Exception {
//    http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
//    http.sessionManagement(
//        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//
//    // if you disable csrf then you can call post method without csrf token.
//    http.csrf(csrf -> csrf.disable());
//    // http.formLogin(withDefaults()); /// this will show login form. disable it if you want
//    // InMemoryUserDetailsManager
//    http.httpBasic(withDefaults());
//    http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
//  //  http.cors(()=>corsConfigurer());
//
//    // enabling frames for h2 console
//    http.headers(
//        headers -> headers.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
//
//    return http.build();
//  }


  //Filter chain
  // authenticate all requests
  //basic authentication
  //disabling csrf
  //stateless rest api

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //1: Response to preflight request doesn't pass access control check
    //2: basic auth
    return
            http
                    .authorizeHttpRequests(
                            auth ->
                                    auth
                                            .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                            .anyRequest().authenticated()
                    )
                    .httpBasic(Customizer.withDefaults())
                    .sessionManagement(
                            session -> session.sessionCreationPolicy
                                    (SessionCreationPolicy.STATELESS))
                    // .csrf().disable() Deprecated in SB 3.1.x
    //.cors(cors -> cors.configurationSource(corsConfigurationSource()))
                    .csrf(csrf -> csrf.disable()) // Starting from SB 3.1.x using Lambda DSL
                    // .csrf(AbstractHttpConfigurer::disable) // Starting from SB 3.1.x using Method Reference
                    .build();
  }
//  @Bean
//  public CorsConfigurationSource corsConfigurationSource() {
//    CorsConfiguration configuration = new CorsConfiguration();
//    configuration.addAllowedOrigin("http://localhost:3000"); // Frontend origin
//    configuration.addAllowedMethod("*"); // Allow all HTTP methods
//    configuration.addAllowedHeader("*"); // Allow all headers
//    configuration.setAllowCredentials(true); // Allow cookies if needed
//    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
//    source.registerCorsConfiguration("/**", configuration); // Apply to all endpoints
//    return source;
//  }

  // Implementation #1 : InMemoryUserDetailsManager
  // comment spring.security crendials  in application property and disable
  // http.formLogin(withDefaults());

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
    var user =
        User.withUsername("mukesh")
            // .password("{noop}upreti")
            .password(passwordEncoder().encode("upreti"))
            .roles("USER")
            .build();
    var admin =
        User.withUsername("admin")
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

//  @Bean
//  public WebMvcConfigurer corsConfigurer() {
//    return new WebMvcConfigurer() {
//      public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedMethods("*")
//                .allowedOrigins("http://localhost:3000");
//      }
//    };
//  }




}
