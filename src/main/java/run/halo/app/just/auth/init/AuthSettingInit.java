package run.halo.app.just.auth.init;

import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.config.AuthDefaultSource;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import reactor.core.publisher.Mono;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.just.auth.extension.AuthSetting;

/**
 * 初始化设置GitHub
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 5:57 PM
 **/
@Slf4j
public class AuthSettingInit {

    private final ReactiveExtensionClient client;

    public AuthSettingInit(ReactiveExtensionClient client) {
        this.client = client;
    }


    @EventListener
    public Mono<Void> initialize(ApplicationReadyEvent readyEvent) {
        return client.fetch(AuthSetting.class, AuthDefaultSource.GITHUB.name().toLowerCase())
                .switchIfEmpty(Mono.defer(() -> {
                    AuthSetting authSetting = new AuthSetting();
                    var metadata = new Metadata();
                    metadata.setName(AuthDefaultSource.GITHUB.name().toLowerCase());
                    authSetting.setOpen(true);
                    authSetting.setDisplayName("GitHub 认证");
                    authSetting.setAuthType(AuthDefaultSource.GITHUB.name());
                    authSetting.setClientId("ec18414ae94c922e24a3");
                    authSetting.setClientSecret("679cff8195d47535db1ccd3fecfb8d9bdddac3f7");
                    authSetting.setAutoRegister(true);
                    authSetting.setUserUniqueField("login");
                    authSetting.setRoleRef("super-role");//默认给一个管理员的
                    authSetting.setOpenProxy(true);
                    authSetting.setProxyHost("127.0.0.1");
                    authSetting.setProxyPort(1080);
                    authSetting.setMetadata(metadata);
                    return client.create(authSetting);
                    }))
                .then();
    }


}
