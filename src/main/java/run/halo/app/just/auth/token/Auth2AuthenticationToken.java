package run.halo.app.just.auth.token;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * JustAuth对接用到的Authentication
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/3 6:26 PM
**/
public class Auth2AuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final Object principal;

	private final String providerId;

	/**
	 * Constructs an {@code Auth2AuthenticationToken} using the provided parameters.
	 * @param principal the user {@code Principal} registered with the OAuth 2.0 Provider
	 * @param authorities the authorities granted to the user
	 * @param providerId the providerId
	 */
	public Auth2AuthenticationToken(Object principal,
                                    Collection<? extends GrantedAuthority> authorities,
                                    String providerId) {
		super(authorities);
		Assert.notNull(principal, "principal cannot be null");
		Assert.hasText(providerId, "providerId cannot be empty");
		this.principal = principal;
		this.providerId = providerId;
		this.setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		// Credentials are never exposed (by the Provider) for an OAuth2 User
		return "";
	}

	/**
	 * 返回第三方服务商id
	 * @return 第三方服务商 id
	 */
	public String getProviderId() {
		return this.providerId;
	}

}
