package run.halo.app.just.auth.utils;

import com.xkcoding.http.config.HttpConfig;
import com.xkcoding.http.constants.Constants;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.Optional;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.request.AuthAlipayRequest;
import me.zhyd.oauth.request.AuthAliyunRequest;
import me.zhyd.oauth.request.AuthAmazonRequest;
import me.zhyd.oauth.request.AuthBaiduRequest;
import me.zhyd.oauth.request.AuthCodingRequest;
import me.zhyd.oauth.request.AuthCsdnRequest;
import me.zhyd.oauth.request.AuthDefaultRequest;
import me.zhyd.oauth.request.AuthDingTalkAccountRequest;
import me.zhyd.oauth.request.AuthDingTalkRequest;
import me.zhyd.oauth.request.AuthDouyinRequest;
import me.zhyd.oauth.request.AuthElemeRequest;
import me.zhyd.oauth.request.AuthFacebookRequest;
import me.zhyd.oauth.request.AuthFeishuRequest;
import me.zhyd.oauth.request.AuthGiteeRequest;
import me.zhyd.oauth.request.AuthGithubRequest;
import me.zhyd.oauth.request.AuthGitlabRequest;
import me.zhyd.oauth.request.AuthGoogleRequest;
import me.zhyd.oauth.request.AuthHuaweiRequest;
import me.zhyd.oauth.request.AuthJdRequest;
import me.zhyd.oauth.request.AuthKujialeRequest;
import me.zhyd.oauth.request.AuthLineRequest;
import me.zhyd.oauth.request.AuthLinkedinRequest;
import me.zhyd.oauth.request.AuthMeituanRequest;
import me.zhyd.oauth.request.AuthMiRequest;
import me.zhyd.oauth.request.AuthMicrosoftCnRequest;
import me.zhyd.oauth.request.AuthMicrosoftRequest;
import me.zhyd.oauth.request.AuthOktaRequest;
import me.zhyd.oauth.request.AuthOschinaRequest;
import me.zhyd.oauth.request.AuthPinterestRequest;
import me.zhyd.oauth.request.AuthProginnRequest;
import me.zhyd.oauth.request.AuthQqRequest;
import me.zhyd.oauth.request.AuthRenrenRequest;
import me.zhyd.oauth.request.AuthSlackRequest;
import me.zhyd.oauth.request.AuthStackOverflowRequest;
import me.zhyd.oauth.request.AuthTaobaoRequest;
import me.zhyd.oauth.request.AuthTeambitionRequest;
import me.zhyd.oauth.request.AuthTwitterRequest;
import me.zhyd.oauth.request.AuthWeChatEnterpriseQrcodeRequest;
import me.zhyd.oauth.request.AuthWeChatEnterpriseThirdQrcodeRequest;
import me.zhyd.oauth.request.AuthWeChatEnterpriseWebRequest;
import me.zhyd.oauth.request.AuthWeChatMpRequest;
import me.zhyd.oauth.request.AuthWeChatOpenRequest;
import me.zhyd.oauth.request.AuthWeiboRequest;
import me.zhyd.oauth.request.AuthXmlyRequest;
import org.springframework.web.util.UriComponentsBuilder;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.consts.SecurityConstants;
import run.halo.app.just.auth.enums.ErrorCodeEnum;
import run.halo.app.just.auth.exception.Auth2Exception;
import run.halo.app.just.auth.extension.AuthSetting;
import run.halo.app.just.auth.properties.JustAuthProperties;
import run.halo.app.just.auth.request.AuthOidcRequest;
import run.halo.app.just.auth.request.config.AuthCustomSource;

/**
 * 根据配置去查询对应的请求体
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/7 6:29 PM
 **/
public final class RequestUtils {

    public static AuthDefaultRequest getRequest(AuthSetting authSetting, HaloProperties haloProperties,
        JustAuthProperties justAuthProperties){
        AuthDefaultRequest authDefaultRequest = null;

        AuthConfig authConfig = new AuthConfig();
        authConfig.setClientId(authSetting.getClientId());
        authConfig.setClientSecret(authSetting.getClientSecret());
        authConfig.setIgnoreCheckState(justAuthProperties.getIgnoreCheckState());
        authConfig.setScopes(authSetting.getScopes());
        authConfig.setStackOverflowKey(authSetting.getStackOverflowKey());
        authConfig.setAgentId(authSetting.getAgentId());
        authConfig.setUsertype(authSetting.getUsertype());
        authConfig.setDomainPrefix(authSetting.getDomainPrefix());
        authConfig.setDeviceId(authSetting.getDeviceId());
        authConfig.setAuthServerId(authSetting.getAuthServerId());
        //是否开启http代理访问
        if(authSetting.isOpenProxy()){
            HttpConfig httpConfig = HttpConfig.builder()
                .proxy(new Proxy(
                    Proxy.Type.HTTP, new InetSocketAddress(authSetting.getProxyHost(), authSetting.getProxyPort())))
                .timeout(authSetting.getProxyTimeout())
                .build();
            authConfig.setHttpConfig(httpConfig);
        }else{
            HttpConfig httpConfig = HttpConfig.builder()
                .timeout(Constants.DEFAULT_TIMEOUT*10)
                .build();
            authConfig.setHttpConfig(httpConfig);
        }

        // 需要拿到重定向的URI metadata.getName是唯一的 这个去获取信息 感觉这里还需要待定一下
        // String redirectUri = haloProperties.getExternalUrl().toString()
        //     + "/" + justAuthProperties.getRedirectUrlPrefix() + "/" + authSetting.getMetadata().getName();
        String redirectUri = haloProperties.getExternalUrl().toString() + SecurityConstants.URL_DEFAULT_SEPARATOR + justAuthProperties.getRedirectUrlPrefix();
        //去掉多余的斜杠
        authConfig.setRedirectUri(UriComponentsBuilder.fromHttpUrl(redirectUri).build().toUriString());

        //优先查询JustAuth已经支持的 然后再去查自定义的
        Optional<AuthDefaultSource> optionalAuthDefaultSource = Arrays.stream(AuthDefaultSource.values()).filter(authDefaultSource -> authDefaultSource.name().equals(authSetting.getAuthType().toUpperCase())).findFirst();
        if(optionalAuthDefaultSource.isPresent()){
            AuthDefaultSource authDefaultSource = optionalAuthDefaultSource.get();
            //需要根据provider来获取对应的类
            switch (authDefaultSource) {
                case GITHUB:
                    authDefaultRequest = new AuthGithubRequest(authConfig);
                    break;
                case WEIBO:
                    authDefaultRequest = new AuthWeiboRequest(authConfig);
                    break;
                case GITEE:
                    authDefaultRequest = new AuthGiteeRequest(authConfig);
                    break;
                case DINGTALK:
                    authDefaultRequest = new AuthDingTalkRequest(authConfig);
                    break;
                case DINGTALK_ACCOUNT:
                    authDefaultRequest = new AuthDingTalkAccountRequest(authConfig);
                    break;
                case BAIDU:
                    authDefaultRequest = new AuthBaiduRequest(authConfig);
                    break;
                case CSDN:
                    // CSDN已被justAuth废弃
                    authDefaultRequest = new AuthCsdnRequest(authConfig);
                    break;
                case CODING:
                    authDefaultRequest = new AuthCodingRequest(authConfig);
                    break;
                case OSCHINA:
                    authDefaultRequest = new AuthOschinaRequest(authConfig);
                    break;
                case ALIPAY:
                    authDefaultRequest = new AuthAlipayRequest(authConfig,authSetting.getAlipayPublicKey());
                    break;
                case QQ:
                    authDefaultRequest = new AuthQqRequest(authConfig);
                    break;
                case WECHAT_OPEN:
                    authDefaultRequest = new AuthWeChatOpenRequest(authConfig);
                    break;
                case WECHAT_MP:
                    authDefaultRequest = new AuthWeChatMpRequest(authConfig);
                    break;
                case TAOBAO:
                    authDefaultRequest = new AuthTaobaoRequest(authConfig);
                    break;
                case GOOGLE:
                    authDefaultRequest = new AuthGoogleRequest(authConfig);
                    break;
                case FACEBOOK:
                    authDefaultRequest = new AuthFacebookRequest(authConfig);
                    break;
                case DOUYIN:
                    authDefaultRequest = new AuthDouyinRequest(authConfig);
                    break;
                case LINKEDIN:
                    authDefaultRequest = new AuthLinkedinRequest(authConfig);
                    break;
                case MICROSOFT:
                    authDefaultRequest = new AuthMicrosoftRequest(authConfig);
                    break;
                case MICROSOFT_CN:
                    authDefaultRequest = new AuthMicrosoftCnRequest(authConfig);
                    break;
                case MI:
                    authDefaultRequest = new AuthMiRequest(authConfig);
                    break;
                case TOUTIAO:
                    authDefaultRequest = new AuthTaobaoRequest(authConfig);
                    break;
                case TEAMBITION:
                    authDefaultRequest = new AuthTeambitionRequest(authConfig);
                    break;
                case RENREN:
                    authDefaultRequest = new AuthRenrenRequest(authConfig);
                    break;
                case PINTEREST:
                    authDefaultRequest = new AuthPinterestRequest(authConfig);
                    break;
                case STACK_OVERFLOW:
                    authDefaultRequest = new AuthStackOverflowRequest(authConfig);
                    break;
                case HUAWEI:
                    authDefaultRequest = new AuthHuaweiRequest(authConfig);
                    break;
                case WECHAT_ENTERPRISE:
                    authDefaultRequest = new AuthWeChatEnterpriseQrcodeRequest(authConfig);
                    break;
                case WECHAT_ENTERPRISE_QRCODE_THIRD:
                    authDefaultRequest = new AuthWeChatEnterpriseThirdQrcodeRequest(authConfig);
                    break;
                case WECHAT_ENTERPRISE_WEB:
                    authDefaultRequest = new AuthWeChatEnterpriseWebRequest(authConfig);
                    break;
                case KUJIALE:
                    authDefaultRequest = new AuthKujialeRequest(authConfig);
                    break;
                case GITLAB:
                    authDefaultRequest = new AuthGitlabRequest(authConfig);
                    break;
                case MEITUAN:
                    authDefaultRequest = new AuthMeituanRequest(authConfig);
                    break;
                case ELEME:
                    authDefaultRequest = new AuthElemeRequest(authConfig);
                    break;
                case TWITTER:
                    authDefaultRequest = new AuthTwitterRequest(authConfig);
                    break;
                case FEISHU:
                    authDefaultRequest = new AuthFeishuRequest(authConfig);
                    break;
                case JD:
                    authDefaultRequest = new AuthJdRequest(authConfig);
                    break;
                case ALIYUN:
                    authDefaultRequest = new AuthAliyunRequest(authConfig);
                    break;
                case XMLY:
                    authDefaultRequest = new AuthXmlyRequest(authConfig);
                    break;
                case AMAZON:
                    authDefaultRequest = new AuthAmazonRequest(authConfig);
                    break;
                case SLACK:
                    authDefaultRequest = new AuthSlackRequest(authConfig);
                    break;
                case LINE:
                    authDefaultRequest = new AuthLineRequest(authConfig);
                    break;
                case OKTA:
                    authDefaultRequest = new AuthOktaRequest(authConfig);
                    break;
                case PROGINN:
                    authDefaultRequest = new AuthProginnRequest(authConfig);
                    break;
                default:
                    break;
            }
        }

        //上面无法查询的话 就从自定义的去查询
        if(authDefaultRequest == null){
            Optional<AuthCustomSource> optionalAuthCustomSource = Arrays.stream(AuthCustomSource.values()).filter(authDefaultSource -> authDefaultSource.name().equals(authSetting.getAuthType().toUpperCase())).findFirst();
            if(optionalAuthCustomSource.isPresent()){
                AuthCustomSource authCustomSource = optionalAuthCustomSource.get();
                switch (authCustomSource){
                    case OIDC:
                        authDefaultRequest = new AuthOidcRequest(authConfig,authSetting);
                        break;
                    default:
                        break;
                }
            }
        }

        if(authDefaultRequest == null){
            throw new Auth2Exception(
                        ErrorCodeEnum.AUTH2_PROVIDER_NOT_SUPPORT, authSetting.getAuthType().toUpperCase());
        }

        return authDefaultRequest;
    }
}
