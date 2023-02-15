package run.halo.app.just.auth.exception;

import lombok.Getter;
import org.springframework.security.core.AuthenticationException;
import run.halo.app.just.auth.enums.ErrorCodeEnum;

/**
 * 第三方授权登录异常
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/6 1:42 PM
**/
public class Auth2Exception extends AuthenticationException {

    @Getter
    private final ErrorCodeEnum errorCodeEnum;
    @Getter
    private final Object data;

    public Auth2Exception(ErrorCodeEnum errorCodeEnum, Object data) {
        super(errorCodeEnum.getMsg());
        this.errorCodeEnum = errorCodeEnum;
        this.data = data;
    }

    public Auth2Exception(ErrorCodeEnum errorCodeEnum, Object data, Throwable cause) {
        super(errorCodeEnum.getMsg(), cause);
        this.errorCodeEnum = errorCodeEnum;
        this.data = data;
    }
}
