package run.halo.app.just.auth.filter.redirect;
import me.zhyd.oauth.request.AuthDefaultRequest;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * 根据路径解析查询提供者
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 1:37 PM
**/
public interface Auth2AuthorizationRequestResolver {

    /**
     * 解析认证源
     * @param exchange
     * @return
     */
	Mono<AuthDefaultRequest> resolve(ServerWebExchange exchange);

    /**
     * 解析认证源
     * @param exchange
     * @param clientRegistrationId
     * @return
     */
    Mono<AuthDefaultRequest> resolve(ServerWebExchange exchange, String clientRegistrationId);


    /**
     * 解析出来的返回认证地址
     * @param exchange
     * @return
     */
    Mono<String> resolveUri(ServerWebExchange exchange);

}