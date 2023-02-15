package run.halo.app.just.auth.entity;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 返回到页面的内容
 * @author ShrChang.Liu
 * @version v1.0
 * @date 2023/2/13 2:49 PM
 **/
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AllowAuthSettingList {

    private List<AllowAuthSetting> data;
}
