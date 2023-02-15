package run.halo.app.just.auth.filter;

import java.net.URI;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.utils.UuidUtils;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.filter.redirect.Auth2DefaultRequestResolver;
import run.halo.app.just.auth.properties.JustAuthProperties;

/**
 * 请求第三方登录的地址然后重定向
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 1:32 PM
 **/
@Slf4j
public class Auth2DefaultRequestRedirectFilter implements WebFilter {

    private final JustAuthProperties justAuthProperties;
    private final HaloProperties haloProperties;
    private final ReactiveExtensionClient client;

    private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();


    public Auth2DefaultRequestRedirectFilter(
        JustAuthProperties justAuthProperties,
        HaloProperties haloProperties,
        ReactiveExtensionClient client){
        this.justAuthProperties = justAuthProperties;
        this.haloProperties = haloProperties;
        this.client = client;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerWebExchangeMatcher serverWebExchangeMatcher = ServerWebExchangeMatchers.pathMatchers(justAuthProperties.getAuthLoginUrlPrefix()+"/**");
        return serverWebExchangeMatcher.matches(exchange)
            .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
            .flatMap(matchResult -> this.getRedirectUri(exchange))
            .flatMap(uri->this.redirectStrategy.sendRedirect(exchange,URI.create(uri)));
    }

    Mono<String> getRedirectUri(ServerWebExchange exchange){
        Auth2DefaultRequestResolver auth2DefaultRequestResolver = new Auth2DefaultRequestResolver(justAuthProperties.getAuthLoginUrlPrefix(),client,justAuthProperties,haloProperties);
        // return auth2DefaultRequestResolver.resolve(exchange)
        //     .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("没有找到对应的提供商"))))
        //     .map(authDefaultRequest -> authDefaultRequest.authorize(UuidUtils.getUUID()));
        return auth2DefaultRequestResolver.resolveUri(exchange);
    }
}
