package run.halo.app.just.auth.extension;

import com.xkcoding.http.constants.Constants;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

/**
 * 认证设置
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 4:54 PM
 **/
@Data
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@GVK(group = "", version = "v1alpha1", kind = "AuthSetting", plural = "authSetting", singular = "authSetting")
public class AuthSetting extends AbstractExtension {

    @Schema(required = true)
    private boolean open; //是否打开

    @Schema(required = true)
    private String displayName;//显示名称

    //针对第三方的需要有一个这个
    private String authUri;
    private String tokenUri;
    private String userInfoUri;
    private String logoutUri;

    private String authType; // 这个地方最好是认证的类型 因为keycloak及其他的可以配置多个 避免可以配置多个的情况

    @Schema(required = true)
    private String clientId;//客户端id：对应各平台的appKey

    @Schema(required = true)
    private String clientSecret;//客户端Secret：对应各平台的appSecret

    private String alipayPublicKey;//公钥 支付宝登录必填

    private String stackOverflowKey;//Stack Overflow Key

    private String agentId;//企业微信，授权方的网页应用ID

    private String usertype;//企业微信第三方授权用户类型，member|admin

    /**
     * 域名前缀。
     * 使用 Coding 登录和 Okta 登录时，需要传该值。
     * Coding 登录：团队域名前缀，比如以“ https://auth.coding.net ”为例，domainPrefix = auth
     * Okta 登录：Okta 账号域名前缀，比如以“ https://auth.okta.com ”为例，domainPrefix = auth
     */
    private String domainPrefix;

    /**
     * 支持自定义授权平台的 scope 内容
     */
    private List<String> scopes;

    /**
     * 设备ID
     */
    private String deviceId;

    /**
     * Okta 授权服务器的 ID， 默认为 default。如果要使用自定义授权服务，此处传实际的授权服务器 ID（一个随机串）
     * 创建自定义授权服务器，请参考：
     * ① https://developer.okta.com/docs/concepts/auth-servers
     * ② https://developer.okta.com/docs/guides/customize-authz-server
     */
    private String authServerId="default";

    @Schema(required = true)
    private boolean openProxy = false;//开启代理

    private Integer proxyTimeout = Constants.DEFAULT_TIMEOUT*10;

    private String proxyHost;
    private Integer proxyPort;

    private String userUniqueField;//用户唯一的字段 需要从返回的原始数据中去选择 如果没有设置的话 默认就是用justauth自己的逻辑默认使用userName

    @Schema(required = true)
    private boolean autoRegister = false;//是否自动注册

    @Schema(required = true)
    private String roleRef;// 如果用户不存在默认绑定的角色

}
