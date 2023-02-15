package run.halo.app.just.auth.config;

import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.filter.Auth2DefaultRequestRedirectFilter;
import run.halo.app.just.auth.filter.Auth2LoginAuthenticationFilter;
import run.halo.app.just.auth.init.AuthSettingInit;
import run.halo.app.just.auth.properties.JustAuthProperties;

/**
 * 默认第三方登录加载SecurityConfig
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 10:58 AM
 **/
@Configuration
@EnableWebFluxSecurity
@AutoConfigureAfter({JustAuthProperties.class,HaloProperties.class})
public class JustAuthWebSecurityConfig {

    private final HaloProperties haloProperties;
    private final JustAuthProperties justAuthProperties;
    private final ReactiveExtensionClient client;
    private final PasswordEncoder passwordEncoder;

    public JustAuthWebSecurityConfig(JustAuthProperties justAuthProperties,
        HaloProperties haloProperties,
        ReactiveExtensionClient client,
        PasswordEncoder passwordEncoder) {
        this.justAuthProperties = justAuthProperties;
        this.haloProperties = haloProperties;
        this.client = client;
        this.passwordEncoder = passwordEncoder;
    }

    @Bean
    Auth2DefaultRequestRedirectFilter auth2DefaultRequestRedirectFilter(){
        return new Auth2DefaultRequestRedirectFilter(justAuthProperties,haloProperties,client);
    }

    @Bean
    Auth2LoginAuthenticationFilter auth2LoginAuthenticationFilter(){
        return new Auth2LoginAuthenticationFilter(justAuthProperties,haloProperties,client,passwordEncoder);
    }

    @Bean
    AuthSettingInit authSettingInit(ReactiveExtensionClient client) {
        return new AuthSettingInit(client);
    }
}
