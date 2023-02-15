package run.halo.app.core.extension;

import static run.halo.app.core.extension.User.GROUP;
import static run.halo.app.core.extension.User.KIND;
import static run.halo.app.core.extension.User.VERSION;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.List;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import run.halo.app.extension.AbstractExtension;
import run.halo.app.extension.GVK;

/**
 * The extension represents user details of Halo.
 *
 * @author johnniang
 */
@Data
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@GVK(group = GROUP,
    version = VERSION,
    kind = KIND,
    singular = "user",
    plural = "users")
public class User extends AbstractExtension {

    public static final String GROUP = "";
    public static final String VERSION = "v1alpha1";
    public static final String KIND = "User";

    public static final String ROLE_NAMES_ANNO = "rbac.authorization.halo.run/role-names";

    @Schema(required = true)
    private UserSpec spec;

    private UserStatus status;

    private List<FederalInfo> federalInfos;//联邦信息

    @Data
    public static class UserSpec {

        @Schema(required = true)
        private String displayName;

        private String avatar;

        @Schema(required = true)
        private String email;

        private String phone;

        private String password;

        private String bio;

        private Instant registeredAt;

        private Boolean twoFactorAuthEnabled;

        private Boolean disabled;

        private Integer loginHistoryLimit;

    }

    @Data
    public static class UserStatus {

        private Instant lastLoginAt;

        private String permalink;

        private List<LoginHistory> loginHistories;

    }

    @Data
    public static class LoginHistory {

        @Schema(required = true)
        private Instant loginAt;

        @Schema(required = true)
        private String sourceIp;

        @Schema(required = true)
        private String userAgent;

        @Schema(required = true)
        private Boolean successful;

        private String reason;

    }

    @Data
    public static class FederalInfo{
        private String proverId;//提供者
        private String authType;//认证来源
        private Instant createAt;//创建时间
        private Instant updateAt;//更新时间
        private String rawUserInfo;//原始用户信息
    }

}
