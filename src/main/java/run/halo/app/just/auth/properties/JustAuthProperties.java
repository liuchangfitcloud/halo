package run.halo.app.just.auth.properties;

import java.time.Duration;
import lombok.Data;
import me.zhyd.oauth.cache.AuthCacheConfig;
import me.zhyd.oauth.model.AuthCallback;
import org.springframework.boot.context.properties.ConfigurationProperties;
import run.halo.app.just.auth.enums.StateCacheType;

/**
 * JustAuth 配置文件属性
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/3 6:25 PM
**/
@Data
@ConfigurationProperties(prefix = "just.auth")
public class JustAuthProperties {

    /**
     * 忽略校验 {@code state} 参数，默认不开启。当 {@code ignoreCheckState} 为 {@code true} 时，
     * {@link me.zhyd.oauth.request.AuthDefaultRequest#login(AuthCallback)} 将不会校验 {@code state} 的合法性。
     * <p>
     * 使用场景：当且仅当使用自实现 {@code state} 校验逻辑时开启
     * <p>
     * 以下场景使用方案仅作参考：
     * 1. 授权、登录为同端，并且全部使用 JustAuth 实现时，该值建议设为 {@code false};
     * 2. 授权和登录为不同端实现时，比如前端页面拼装 {@code authorizeUrl}，并且前端自行对{@code state}进行校验，
     * 后端只负责使用{@code code}获取用户信息时，该值建议设为 {@code true};
     *
     * <strong>如非特殊需要，不建议开启这个配置</strong>
     * <p>
     * 该方案主要为了解决以下类似场景的问题：
     *
     * @see <a href="https://github.com/justauth/JustAuth/issues/83">https://github.com/justauth/JustAuth/issues/83</a>
     * @since 1.15.6
     */
    private Boolean ignoreCheckState = false;

    /**
     * 默认 state 缓存过期时间：3分钟(PT180S)
     * 鉴于授权过程中，根据个人的操作习惯，或者授权平台的不同（google等），每个授权流程的耗时也有差异，不过单个授权流程一般不会太长
     * 本缓存工具默认的过期时间设置为3分钟，即程序默认认为3分钟内的授权有效，超过3分钟则默认失效，失效后删除
     */
    private Duration timeout = Duration.ofMillis(AuthCacheConfig.timeout);

    /**
     * JustAuth state 缓存类型, 现在就是默认的缓存没有做任何更改
     * {@link  me.zhyd.oauth.cache.AuthDefaultStateCache}
     */
    private StateCacheType cacheType = StateCacheType.DEFAULT;

    /**
     * JustAuth state 缓存 key 前缀
     */
    private String cacheKeyPrefix = "JUST_AUTH:";

    /**
     * 第三方登录回调处理 url 前缀 默认拼接是halo.external-url + this 请注意分隔符<br><br>
     */
    private String redirectUrlPrefix = "/auth2/login";

    /**
     * 第三方登录授权登录 url 前缀. 默认拼接是halo.external-url + this注意分隔符<br><br>
     */
    private String authLoginUrlPrefix = "/auth2/authorization";

    /**
     * 用户注册时默认的密码信息
     */
    private String defaultUserPassword = "halo";

}