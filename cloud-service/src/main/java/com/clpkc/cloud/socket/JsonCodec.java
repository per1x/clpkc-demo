package com.clpkc.cloud.socket;

import java.util.LinkedHashMap;
import java.util.Map;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * NDJSON 行消息编解码（键值均为字符串）。使用 Jackson，替换原 Demo 的玩具解析器。
 */
public final class JsonCodec {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<LinkedHashMap<String, String>> MAP_TYPE =
        new TypeReference<>() {
        };

    private JsonCodec() {
    }

    public static Map<String, String> parse(String line) {
        try {
            Map<String, String> map = MAPPER.readValue(line, MAP_TYPE);
            if (map == null) {
                throw new IllegalArgumentException("empty json object");
            }
            return map;
        } catch (Exception e) {
            throw new IllegalArgumentException("malformed json line", e);
        }
    }

    public static String stringify(Map<String, String> body) {
        try {
            return MAPPER.writeValueAsString(body);
        } catch (Exception e) {
            throw new IllegalStateException("json serialization failed", e);
        }
    }
}
