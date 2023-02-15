package run.halo.app.just.auth.filter.redirect;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.STATE;

import java.nio.charset.StandardCharsets;
import java.nio.file.ProviderNotFoundException;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.request.AuthDefaultRequest;
import me.zhyd.oauth.utils.UuidUtils;
import org.springframework.lang.Nullable;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.Base64Utils;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.consts.SecurityConstants;
import run.halo.app.just.auth.enums.ErrorCodeEnum;
import run.halo.app.just.auth.exception.Auth2Exception;
import run.halo.app.just.auth.extension.AuthSetting;
import run.halo.app.just.auth.properties.JustAuthProperties;
import run.halo.app.just.auth.utils.RequestUtils;

/**
 * <p>
 *  解析路径中所带的提供者信息
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 1:44 PM
**/
@Slf4j
public final class Auth2DefaultRequestResolver implements Auth2AuthorizationRequestResolver {

	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "providerId";

    private final ServerWebExchangeMatcher serverWebExchangeMatcher;
    private final ReactiveExtensionClient client;
    private final JustAuthProperties justAuthProperties;
    private final HaloProperties haloProperties;

	/**
	 * Constructs a {@code Auth2DefaultRequestResolver} using the provided
	 * parameters.
	 * @param authorizationRequestBaseUri the base {@code URI} used for resolving
	 * authorization requests
	 */
	public Auth2DefaultRequestResolver(String authorizationRequestBaseUri,ReactiveExtensionClient client,JustAuthProperties justAuthProperties,
        HaloProperties haloProperties) {
		Assert.hasText(authorizationRequestBaseUri, "authorizationRequestBaseUri cannot be empty");
		this.serverWebExchangeMatcher = new PathPatternParserServerWebExchangeMatcher(authorizationRequestBaseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
	    this.client = client;
        this.justAuthProperties = justAuthProperties;
        this.haloProperties = haloProperties;
    }

	@Override
	public Mono<AuthDefaultRequest> resolve(ServerWebExchange exchange) {
		if (StringUtils.hasText(exchange.getRequest().getQueryParams().getFirst(STATE))) {
            return Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.SERVER_ERROR,"")));
		}
        try {
            return this.resolveRegistrationId(exchange).flatMap(this::getAuth2DefaultRequest);
        }catch (Exception e){
            return Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.SERVER_ERROR,"")));
        }
	}

	@Override
	public Mono<AuthDefaultRequest> resolve(ServerWebExchange exchange, String providerId){
		if (StringUtils.hasText(exchange.getRequest().getQueryParams().getFirst(STATE))) {
            return Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.SERVER_ERROR,"")));
		}
		return getAuth2DefaultRequest(providerId);
	}

    @Override
    public Mono<String> resolveUri(ServerWebExchange exchange) {
        if (StringUtils.hasText(exchange.getRequest().getQueryParams().getFirst(STATE))) {
            return Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.SERVER_ERROR,"已经包含了状态信息")));
        }
        try {
            return this.resolveRegistrationId(exchange)
                .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("没有找到认证提供商"))))
                .flatMap(providerId->getRedictUri(providerId)).flatMap(uri->this.log(uri).thenReturn(uri));
        }catch (Exception e){
            return Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.SERVER_ERROR,e)));
        }
    }

    private Mono<Void> log(String uri){
        log.info("回调地址:{}",uri);
        return Mono.empty();
    }

    private Mono<String> getRedictUri(String providerId){
        String originalState = providerId + SecurityConstants.STATE_DEFAULT_SEPARATOR + UuidUtils.getUUID();
        String state = Base64Utils.encodeToUrlSafeString(originalState.getBytes(StandardCharsets.UTF_8));
        return getAuth2DefaultRequest(providerId)
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("没有找到认证提供商"))))
            .map(authDefaultRequest -> authDefaultRequest.authorize(state));
    }

    /**
     * 返回异常处理
     * @author ShrChang.Liu
     * @version v1.0
     * @date 2023/2/7 1:48 PM
    **/
	public Mono<String> resolveRegistrationId(ServerWebExchange exchange) {
         return this.serverWebExchangeMatcher.matches(exchange)
             .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
             .switchIfEmpty(Mono.defer(()->Mono.error(new Auth2Exception(ErrorCodeEnum.AUTH2_PROVIDER_NOT_SUPPORT,""))))
             .map(matchResult -> (String)matchResult.getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME));
	}

	@Nullable
	private Mono<AuthDefaultRequest> getAuth2DefaultRequest(@Nullable String providerId){
        //根据类型去查询返回的内容
        return client.fetch(AuthSetting.class,providerId)
            .filter(AuthSetting::isOpen)
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("未找到登录配置"))))
            .map(authSetting -> RequestUtils.getRequest(authSetting,haloProperties,justAuthProperties));
	}
}