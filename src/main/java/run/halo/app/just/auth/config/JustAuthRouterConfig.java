package run.halo.app.just.auth.config;

import static org.springdoc.core.fn.builders.apiresponse.Builder.responseBuilder;
import static org.springdoc.core.fn.builders.parameter.Builder.parameterBuilder;

import io.swagger.v3.oas.annotations.enums.ParameterIn;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import org.springdoc.webflux.core.fn.SpringdocRouteBuilder;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebInputException;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import run.halo.app.extension.ExtensionOperator;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.consts.SecurityConstants;
import run.halo.app.just.auth.entity.AllowAuthSetting;
import run.halo.app.just.auth.entity.AllowAuthSettingList;
import run.halo.app.just.auth.entity.AuthSettingCallBackUri;
import run.halo.app.just.auth.extension.AuthSetting;
import run.halo.app.just.auth.properties.JustAuthProperties;

/**
 * 自定义路由地址
 *
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/13 2:09 PM
 **/
@Configuration
@AutoConfigureAfter({JustAuthProperties.class, HaloProperties.class})
public class JustAuthRouterConfig {

    private final HaloProperties haloProperties;
    private final JustAuthProperties justAuthProperties;
    private final ReactiveExtensionClient client;

    public JustAuthRouterConfig(JustAuthProperties justAuthProperties,
        HaloProperties haloProperties,
        ReactiveExtensionClient client) {
        this.justAuthProperties = justAuthProperties;
        this.haloProperties = haloProperties;
        this.client = client;
    }

    @Bean
    public RouterFunction<ServerResponse> justAuthRouterFunction() {
        SpringdocRouteBuilder routeBuilder = SpringdocRouteBuilder.route();
        // 添加一个可以查询返回参数的
        routeBuilder.GET("/api/v1alpha1/authSetting/{name}/getCallbackUri", this::callbackUri,
            builder -> builder.operationId("Get AuthSetting callback Uri")
                .description("Get AuthSetting callback Uri")
                .tag("v1alpha1/AuthSetting")
                .parameter(parameterBuilder().in(ParameterIn.PATH).name("name")
                    .description("AuthSetting Name")
                    .required(true))
                .response(responseBuilder().implementation(AuthSettingCallBackUri.class)));

        routeBuilder.GET("/apis/api.halo.run/v1alpha1/authSetting/allowList", this::getAllowList,
            builder -> builder.operationId("Get AuthSetting Allow List")
                .description("Get AuthSetting Allow List")
                .tag("api.halo.run/v1alpha1/authSetting")
                .response(responseBuilder().implementation(AllowAuthSettingList.class)));

        return routeBuilder.build();
    }

    @NonNull
    Mono<ServerResponse> getAllowList(ServerRequest request) {
        return client.list(AuthSetting.class, isOpen(), null).collectList()
            .flatMap(authSettings -> {
                List<AllowAuthSetting> allowAuthSettingList = new ArrayList<>();
                authSettings.stream().forEach(authSetting -> allowAuthSettingList.add(
                    AllowAuthSetting.builder().authType(authSetting.getAuthType())
                        .displayName(authSetting.getDisplayName())
                        .name(authSetting.getMetadata().getName())
                        .uri(justAuthProperties.getAuthLoginUrlPrefix() + SecurityConstants.URL_DEFAULT_SEPARATOR
                            + authSetting.getMetadata().getName()).build()));
                return Mono.just(AllowAuthSettingList.builder().data(allowAuthSettingList).build());
            }).flatMap(
                allowAuthSettingList -> ServerResponse.ok().contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(allowAuthSettingList));
    }

    public static Predicate<AuthSetting> isOpen() {
        return ExtensionOperator.<AuthSetting>isNotDeleted()
            .and(authSetting -> authSetting.isOpen());
    }

    @NonNull
    Mono<ServerResponse> callbackUri(ServerRequest request) {
        String name = request.pathVariable("name");
        String externalUrl = haloProperties.getExternalUrl().toString();
        // String baseUri = externalUrl + SecurityConstants.URL_DEFAULT_SEPARATOR + justAuthProperties.getRedirectUrlPrefix() + SecurityConstants.URL_DEFAULT_SEPARATOR + name;
        String baseUri = externalUrl + SecurityConstants.URL_DEFAULT_SEPARATOR + justAuthProperties.getRedirectUrlPrefix();
        String uri = UriComponentsBuilder.fromHttpUrl(baseUri).toUriString();
        return client.fetch(AuthSetting.class, name)
            .switchIfEmpty(Mono.error(() -> new ServerWebInputException("Not Found AuthSetting!")))
            .flatMap(authSetting -> ServerResponse.ok()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(AuthSettingCallBackUri.builder().uri(uri).build()));
    }
}
