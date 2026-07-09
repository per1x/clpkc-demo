package com.clpkc.cloud.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 桩编号核对对接点。
 *
 * <p>第二阶段（会话协商）时，云平台需要确认来访的桩编号是合法/被授权的。
 * 云平台已有全量桩编号系统，此处仅留对接点。</p>
 */
@Service
public class PileDirectory {

    private static final Logger log = LoggerFactory.getLogger(PileDirectory.class);

    /**
     * 校验桩编号是否存在且被授权。
     *
     * <p><b>TODO 对接：</b>此处应调用云平台既有的桩编号系统，查询该 {@code pileId} 是否存在、
     * 是否处于启用状态（以及必要时核对其登记的无证书声明公钥）。当前为占位实现，默认放行。</p>
     *
     * @param pileId 桩编号
     * @return 是否允许继续会话协商
     */
    public boolean isAuthorized(String pileId) {
        // === 对接云平台既有桩编号系统：改为真实查询 ===
        log.info("[Cloud] 桩编号核对(占位放行): {}", pileId);
        return true;
    }
}
