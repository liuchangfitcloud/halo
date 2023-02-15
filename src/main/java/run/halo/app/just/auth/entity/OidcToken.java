package run.halo.app.just.auth.entity;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.Data;

/**
 * 返回的token
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/14 12:12 PM
 **/
@Data
public class OidcToken {
    @JSONField(name = "access_token")
    private String accessToken;

    @JSONField(name = "expires_in")
    private Integer expiresIn;

    @JSONField(name = "id_token")
    private String idToken;

    @JSONField(name = "refresh_expires_in")
    private Integer refreshExpiresIn;

    @JSONField(name = "refresh_token")
    private String refreshToken;

    @JSONField(name = "token_type")
    private String tokenType;

    @JSONField(name = "not-before-policy")
    private Integer notBeforePolicy;

    @JSONField(name = "session_state")
    private String sessionState;

    private String scope;
}
