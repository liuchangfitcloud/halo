package run.halo.app.just.auth.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 返回信息
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/13 2:41 PM
 **/
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthSettingCallBackUri {
    private String uri;
}
