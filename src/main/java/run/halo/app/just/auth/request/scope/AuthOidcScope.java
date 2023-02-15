package run.halo.app.just.auth.request.scope;

import me.zhyd.oauth.enums.scope.AuthScope;

/**
 * oidc的作用域
 *
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/14 11:02 AM
 **/
public enum AuthOidcScope implements AuthScope {
    OPENID("openid", "获取用户ID", true),
    PROFILE("profile", "获取个人信息", true),
    EMAIL("email", "读取邮件地址", true);


    private final String scope;
    private final String description;
    private final boolean isDefault;

    public String getScope() {
        return this.scope;
    }

    public String getDescription() {
        return this.description;
    }

    public boolean isDefault() {
        return this.isDefault;
    }

    private AuthOidcScope(String scope, String description, boolean isDefault) {
        this.scope = scope;
        this.description = description;
        this.isDefault = isDefault;
    };
}
