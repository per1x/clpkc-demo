package demo.clpkc.cloud;

import java.util.LinkedHashMap;
import java.util.Map;

public final class SimpleJson {
    private SimpleJson() {
    }

    public static Map<String, String> parse(String json) {
        Map<String, String> out = new LinkedHashMap<>();
        String body = json.trim();
        body = body.substring(1, body.length() - 1).trim();
        if (body.isEmpty()) {
            return out;
        }
        int index = 0;
        while (index < body.length()) {
            int keyStart = body.indexOf('"', index);
            int keyEnd = body.indexOf('"', keyStart + 1);
            int colon = body.indexOf(':', keyEnd + 1);
            int valueStart = body.indexOf('"', colon + 1);
            int valueEnd = body.indexOf('"', valueStart + 1);
            String key = body.substring(keyStart + 1, keyEnd);
            String value = body.substring(valueStart + 1, valueEnd);
            out.put(key, value);
            index = valueEnd + 1;
            if (index < body.length() && body.charAt(index) == ',') {
                index++;
            }
        }
        return out;
    }

    public static String stringify(Map<String, String> map) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, String> entry : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(entry.getKey()).append("\":\"").append(entry.getValue()).append('"');
        }
        sb.append('}');
        return sb.toString();
    }
}
