package run.halo.app.just.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import run.halo.app.just.auth.properties.JustAuthProperties;

/**
 * 配置文件加载
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 10:15 AM
**/
@Configuration
@EnableConfigurationProperties({JustAuthProperties.class})
public class Auth2PropertiesAutoConfiguration {

}