package run.halo.app.just.auth.request;

import cn.hutool.core.util.CharsetUtil;
import cn.hutool.http.ContentType;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import com.xkcoding.http.support.SimpleHttpResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthDefaultRequest;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.UrlBuilder;
import run.halo.app.just.auth.entity.OidcToken;
import run.halo.app.just.auth.enums.ErrorCodeEnum;
import run.halo.app.just.auth.exception.Auth2Exception;
import run.halo.app.just.auth.extension.AuthSetting;
import run.halo.app.just.auth.request.config.AuthCustomSource;
import run.halo.app.just.auth.request.scope.AuthOidcScope;

/**
 * OIDC实现的认证基础类
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/14 10:24 AM
 **/
@Slf4j
public class AuthOidcRequest extends AuthDefaultRequest {

    private final AuthSetting authSetting;

    public AuthOidcRequest(AuthConfig config,AuthSetting authSetting) {
        super(config, AuthCustomSource.OIDC);
        this.authSetting = authSetting;
    }

    @Override
    public String authorize(String state) {
        return UrlBuilder.fromBaseUrl(authSetting.getAuthUri())
            .queryParam("response_type", "code")
            .queryParam("client_id", config.getClientId())
            .queryParam("redirect_uri", config.getRedirectUri())
            .queryParam("scope", this.getScopes("+", false, AuthScopeUtils.getDefaultScopes(
                AuthOidcScope.values())))
            .queryParam("state", getRealState(state))
            .build();
    }

    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        Map<String, String> requetMap = new LinkedHashMap<>();
        //接口参数
        requetMap.put("code", authCallback.getCode());
        requetMap.put("client_id", config.getClientId());
        requetMap.put("client_secret", config.getClientSecret());
        requetMap.put("grant_type", "authorization_code");
        requetMap.put("redirect_uri", config.getRedirectUri());
        HttpHeader header = new HttpHeader();
        header.add(Constants.CONTENT_TYPE, ContentType.FORM_URLENCODED.toString(CharsetUtil.CHARSET_UTF_8));
        SimpleHttpResponse response = new HttpUtils(config.getHttpConfig()).post(authSetting.getTokenUri(),requetMap,header,false).getHttpResponse();
        if(response.getCode() == 200){
            OidcToken oidcToken = JSON.parseObject(response.getBody(), OidcToken.class);
            return AuthToken.builder()
                .accessToken(oidcToken.getAccessToken())
                .tokenType(oidcToken.getTokenType())
                .expireIn(oidcToken.getExpiresIn())
                .refreshToken(oidcToken.getRefreshToken())
                .refreshTokenExpireIn(oidcToken.getRefreshExpiresIn())
                .idToken(oidcToken.getIdToken())
                .scope(oidcToken.getScope())
                .build();
        }else{
            throw new Auth2Exception(ErrorCodeEnum.PARAMETER_ERROR,response.getBody());
        }
    }


    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        //获取用户信息
        HttpHeader header = new HttpHeader();
        header.add("Authorization","Bearer " + authToken.getAccessToken());
        SimpleHttpResponse response = new HttpUtils(config.getHttpConfig()).get(authSetting.getUserInfoUri(),null,header,false).getHttpResponse();
        if(response.getCode() == 200){
            JSONObject jsonObject = JSONObject.parseObject(response.getBody());
            return AuthUser.builder()
                .username(jsonObject.getString("preferred_username"))
                .email(jsonObject.getString("email"))
                .nickname(jsonObject.getString("name"))
                .token(authToken)
                .uuid(jsonObject.getString("sub"))
                .rawUserInfo(jsonObject)
                .build();
        }
        throw new Auth2Exception(ErrorCodeEnum.QUERY_USER_INFO_ERROR,authToken);
    }
}
