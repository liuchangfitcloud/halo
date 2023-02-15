package run.halo.app.just.auth.filter;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;
import static run.halo.app.core.extension.User.GROUP;
import static run.halo.app.core.extension.User.KIND;

import com.alibaba.fastjson.JSON;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.AuthDefaultRequest;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Base64Utils;
import org.springframework.util.CollectionUtils;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import run.halo.app.core.extension.Role;
import run.halo.app.core.extension.RoleBinding;
import run.halo.app.core.extension.User;
import run.halo.app.extension.GroupKind;
import run.halo.app.extension.Metadata;
import run.halo.app.extension.ReactiveExtensionClient;
import run.halo.app.infra.properties.HaloProperties;
import run.halo.app.just.auth.consts.SecurityConstants;
import run.halo.app.just.auth.extension.AuthSetting;
import run.halo.app.just.auth.properties.JustAuthProperties;
import run.halo.app.just.auth.token.Auth2AuthenticationToken;
import run.halo.app.just.auth.utils.RequestUtils;

/**
 * 回调过来处理认证信息的 并且需要完成登录
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 11:54 AM
 **/
@Slf4j
public class Auth2LoginAuthenticationFilter implements WebFilter {

    private final String REGISTRATION_ID_URI_VARIABLE_NAME = "providerId";

    private final JustAuthProperties justAuthProperties;
    private final HaloProperties haloProperties;
    private final ReactiveExtensionClient client;
    private final PasswordEncoder passwordEncoder;
    private ServerSecurityContextRepository securityContextRepository =
        NoOpServerSecurityContextRepository
            .getInstance();
    private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

    public Auth2LoginAuthenticationFilter(JustAuthProperties justAuthProperties,
        HaloProperties haloProperties,
        ReactiveExtensionClient client,
        PasswordEncoder passwordEncoder){
        this.justAuthProperties = justAuthProperties;
        this.haloProperties = haloProperties;
        this.client = client;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerWebExchangeMatcher serverWebExchangeMatcher = pathMatchers(justAuthProperties.getRedirectUrlPrefix(),justAuthProperties.getRedirectUrlPrefix()+"/*");
        return serverWebExchangeMatcher.matches(exchange)
            .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
            .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
            .flatMap(matchResult-> this.getProviderId(exchange))
            .flatMap(proverdId -> authenticate(proverdId,exchange))
            .flatMap(authentication -> this.redirectStrategy.sendRedirect(exchange, URI.create("/console")));
    }

    /**
     * 根据state返回的参数去查
     * @param exchange
     * @return
     */
    Mono<String> getProviderId(ServerWebExchange exchange){
        MultiValueMap<String, String> multiValueMap = exchange.getRequest().getQueryParams();
        AuthCallback authCallback =JSON.parseObject(JSON.toJSONString(multiValueMap.toSingleValueMap()), AuthCallback.class);
        if(!StringUtils.hasText(authCallback.getState())){
            return getProviderIdByPath(exchange);
        }else{
            return Mono.just(authCallback.getState()).map(state->{
               String originalState = new String(Base64Utils.decodeFromUrlSafeString(state), StandardCharsets.UTF_8);
               return originalState.split(SecurityConstants.STATE_DEFAULT_SEPARATOR)[0];
            });
        }
    }

    /**
     * 根据路径获取provider
     * @author ShrChang.Liu
     * @version v1.0
     * @date 2023/2/7 5:16 PM
    **/
    Mono<String> getProviderIdByPath(ServerWebExchange exchange){
        PathPatternParserServerWebExchangeMatcher pathPatternParserServerWebExchangeMatcher = new PathPatternParserServerWebExchangeMatcher(justAuthProperties.getRedirectUrlPrefix() + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
        return pathPatternParserServerWebExchangeMatcher.matches(exchange)
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("URL不匹配"))))
            .map(matchResult -> matchResult.getVariables().get(REGISTRATION_ID_URI_VARIABLE_NAME))
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("没有找到提供商"))))
            .map(obj->(String)obj);
    }

    /**
     * 构建用户凭据
     * @param providerId
     * @param exchange
     * @return
     */
    Mono<Authentication> authenticate(String providerId,ServerWebExchange exchange){
        return client.fetch(AuthSetting.class,providerId)
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("提供商配置未找到"))))
            .filter(AuthSetting::isOpen)
            .switchIfEmpty(Mono.defer(()->Mono.error(new ProviderNotFoundException("提供商配置未开启"))))
            .flatMap(authSetting -> exchangToken(authSetting,exchange))
            .flatMap(authentication -> onSuccess(authentication).thenReturn(authentication));
    }

    private Mono<Void> onSuccess(Authentication token) {
        return onAuthenticationSuccess(token);
    }

    //不知道这样对不对
    protected Mono<Void> onAuthenticationSuccess(Authentication authentication) {
        return ReactiveSecurityContextHolder.getContext().flatMap(securityContext -> {
            log.info("*********come in ******");
            securityContext.setAuthentication(authentication);
            return Mono.empty();
        }).then();
    }

    /**
     * 登录并返回用户信息 再去判断是不是数据库已经存在新增用户与角色的绑定关系
     * @param authDefaultRequest
     * @param exchange
     * @return
     */
    AuthUser login(AuthDefaultRequest authDefaultRequest,ServerWebExchange exchange) {
        MultiValueMap<String, String> multiValueMap = exchange.getRequest().getQueryParams();
        AuthCallback authCallback =JSON.parseObject(JSON.toJSONString(multiValueMap.toSingleValueMap()), AuthCallback.class);
        AuthResponse authResponse = authDefaultRequest.login(authCallback);
        if(authResponse.ok()){
            AuthUser authUser = (AuthUser) authResponse.getData();
            log.info("auth User info:{}",JSON.toJSONString(authUser));
            return authUser;
        }
        return null;
    }

    /**
     * 返回实现类
     * @param authSetting
     * @return
     */
    AuthDefaultRequest getRequest(AuthSetting authSetting) {
        return RequestUtils.getRequest(authSetting,haloProperties,justAuthProperties);
    }

    /**
     * 获取用户ID
     * @param authSetting
     * @param authUser
     * @return
     */
    private String getUserId(AuthSetting authSetting, AuthUser authUser) {
        String userId = authUser.getUsername();
        if(StringUtils.hasText(authSetting.getUserUniqueField())){
            if(!authUser.getRawUserInfo().containsKey(authSetting.getUserUniqueField()))
                throw new UsernameNotFoundException("无法获取用户唯一标识");
            userId = authUser.getRawUserInfo().getString(authSetting.getUserUniqueField());
        }
        return userId;
    }

    /**
     * 获取Token信息并验证
     * @param authSetting
     * @param exchange
     */
    Mono<Authentication> exchangToken(AuthSetting authSetting,ServerWebExchange exchange)throws AuthenticationException{
        AuthDefaultRequest authDefaultRequest = getRequest(authSetting);
        if(authDefaultRequest == null)
            throw new ProviderNotFoundException("提供商未找到");
        AuthUser authUser = login(authDefaultRequest,exchange);
        if(authUser == null)
            throw new UsernameNotFoundException("未找到用户信息");
        authUser.setSource(authSetting.getMetadata().getName());
        //查询用户是不是存在
        String userId = getUserId(authSetting, authUser);
        //判断用户是否已经存在 未存在直接抛出异常
        return client.fetch(User.class,userId)
            .switchIfEmpty(Mono.defer(() -> addUser(authSetting,authUser)))
            .flatMap(user->commentUser(user,authUser,authSetting).thenReturn(user))
            .flatMap(this::getUserDetails)
            .map(userDetails -> getAuthentication(userDetails,authSetting));
    }

    /**
     * 更新用户信息
     * @param user
     * @param authUser
     * @param authSetting
     * @return
     */
    Mono<Void> commentUser(User user,AuthUser authUser,AuthSetting authSetting){
        if(StringUtils.hasText(authUser.getNickname())){
            user.getSpec().setDisplayName(authUser.getNickname());
        }
        if(StringUtils.hasText(authUser.getAvatar())){
            user.getSpec().setAvatar(authUser.getAvatar());
        }
        if(StringUtils.hasText(authUser.getEmail())){
            user.getSpec().setEmail(authUser.getEmail());
        }
        if(CollectionUtils.isEmpty(user.getFederalInfos())){
            user.setFederalInfos(new ArrayList<>());
        }
        Optional<User.FederalInfo> optional = user.getFederalInfos().stream()
            .filter(federalInfo -> federalInfo.getProverId().equals(authSetting.getMetadata().getName()))
            .findFirst();
        if(optional.isPresent()){
            User.FederalInfo fi = optional.get();
            fi.setAuthType(authSetting.getAuthType());
            fi.setRawUserInfo(JSON.toJSONString(authUser.getRawUserInfo()));
            fi.setUpdateAt(Instant.now());
        }else{
            User.FederalInfo fi = new User.FederalInfo();
            fi.setProverId(authSetting.getMetadata().getName());
            fi.setAuthType(authSetting.getAuthType());
            fi.setRawUserInfo(JSON.toJSONString(authSetting));
            fi.setCreateAt(Instant.now());
            fi.setUpdateAt(Instant.now());
            user.getFederalInfos().add(fi);
        }
        return client.update(user).then();
    }

    Mono<UserDetails> getUserDetails(User user){
        //查询他的权限放到信息里面
        var subject = new RoleBinding.Subject(KIND, user.getMetadata().getName(), GROUP);
        return client.list(RoleBinding.class,
            binding -> binding.getSubjects().contains(subject),
            null)
            .map(RoleBinding::getRoleRef)
            .filter(this::isRoleRef)
            .map(RoleBinding.RoleRef::getName)
            .collectList()
            .map(roleNames ->
                 org.springframework.security.core.userdetails.User.builder()
                .username(user.getMetadata().getName())
                .password(user.getSpec().getPassword())
                .roles(roleNames.toArray(new String[0]))
                .build());
    }

    /**
     * 判断是不是角色
     * @param roleRef
     * @return
     */
    private boolean isRoleRef(RoleBinding.RoleRef roleRef) {
        var roleGvk = new Role().groupVersionKind();
        var gk = new GroupKind(roleRef.getApiGroup(), roleRef.getKind());
        return gk.equals(roleGvk.groupKind());
    }


    /**
     * 构建一个新的认证token
     * @param userDetails
     * @param authSetting
     * @return
     */
    Authentication getAuthentication(UserDetails userDetails,AuthSetting authSetting){
        Auth2AuthenticationToken authentication = new Auth2AuthenticationToken(userDetails.getUsername(),userDetails.getAuthorities(),authSetting.getMetadata().getName());
        return authentication;
    }

    /**
     * 判断是否添加用户
     * @param authSetting
     * @param authUser
     * @return
     * @throws AuthenticationException
     */
    Mono<User> addUser(AuthSetting authSetting,AuthUser authUser)throws AuthenticationException{
        if(authSetting.isAutoRegister()){
            String userId = getUserId(authSetting, authUser);
            return client.create(createUser(userId,authUser)).flatMap(user -> bindUserAndRole(user,authSetting));
        }
        throw new ProviderNotFoundException("未找到用户");
    }

    /**
     * 创建角色绑定
     * @param user
     * @param authSetting
     * @return
     */
    Mono<User> bindUserAndRole(User user,AuthSetting authSetting) {
        var metadata = new Metadata();
        String name =
            String.join("-", user.getMetadata().getName(), authSetting.getRoleRef(), "binding");
        metadata.setName(name);
        var roleRef = new RoleBinding.RoleRef();
        roleRef.setName(authSetting.getRoleRef());
        roleRef.setApiGroup(Role.GROUP);
        roleRef.setKind(Role.KIND);

        var subject = new RoleBinding.Subject();
        subject.setName(user.getMetadata().getName());
        subject.setApiGroup(user.groupVersionKind().group());
        subject.setKind(user.groupVersionKind().kind());

        var roleBinding = new RoleBinding();
        roleBinding.setMetadata(metadata);
        roleBinding.setRoleRef(roleRef);
        roleBinding.setSubjects(List.of(subject));

        return client.fetch(RoleBinding.class,roleBinding.getMetadata().getName())
            .switchIfEmpty(Mono.defer(() -> client.create(roleBinding)))
            .flatMap(rb -> {
                rb.setRoleRef(roleRef);
                rb.setSubjects(List.of(subject));
                return client.update(rb);
            }).thenReturn(user);
    }

    /**
     * 构建用户
     * @param userId
     * @param authUser
     * @return
     */
    User createUser(String userId,AuthUser authUser) {
        var metadata = new Metadata();
        metadata.setName(userId);

        var spec = new User.UserSpec();
        if(StringUtils.hasText(authUser.getNickname())){
            spec.setDisplayName(authUser.getNickname());
        }else{
            spec.setDisplayName(authUser.getUsername());
        }
        spec.setDisabled(false);
        spec.setRegisteredAt(Instant.now());
        spec.setAvatar(authUser.getAvatar());
        spec.setTwoFactorAuthEnabled(false);
        if(StringUtils.hasText(authUser.getEmail())){
            spec.setEmail(authUser.getEmail());
        }else{
            spec.setEmail(authUser.getUsername()+"@halo.run");
        }

        //先默认密码是admin
        if(StringUtils.hasText(justAuthProperties.getDefaultUserPassword())){
            spec.setPassword(passwordEncoder.encode(justAuthProperties.getDefaultUserPassword()));
        }else{
            spec.setPassword(passwordEncoder.encode("halo"));
        }


        var user = new User();
        user.setMetadata(metadata);
        user.setSpec(spec);
        return user;
    }

}
