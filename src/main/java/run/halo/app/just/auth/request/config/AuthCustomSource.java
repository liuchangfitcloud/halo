package run.halo.app.just.auth.request.config;

import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.request.AuthDefaultRequest;
import run.halo.app.just.auth.request.AuthOidcRequest;

/**
 *
 * 自定义的元数据
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/14 10:27 AM
 **/
public enum AuthCustomSource implements AuthSource {
    OIDC {
        @Override
        public String authorize() {
            return "";
        }

        @Override
        public String accessToken() {
            return "";
        }

        @Override
        public String userInfo() {
            return "";
        }

        @Override
        public Class<? extends AuthDefaultRequest> getTargetClass() {
            return AuthOidcRequest.class;
        }
    }
}
