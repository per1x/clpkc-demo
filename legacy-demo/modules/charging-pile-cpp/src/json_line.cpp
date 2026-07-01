#include "json_line.h"

std::string json_stringify(const std::map<std::string, std::string>& kv) {
    std::string out = "{";
    bool first = true;
    for (const auto& [k, v] : kv) {
        if (!first) {
            out += ",";
        }
        first = false;
        out += "\"" + k + "\":\"" + v + "\"";
    }
    out += "}";
    return out;
}

std::map<std::string, std::string> json_parse(const std::string& json) {
    std::map<std::string, std::string> out;
    std::size_t i = 0;
    while (true) {
        std::size_t ks = json.find('"', i);
        if (ks == std::string::npos) {
            break;
        }
        std::size_t ke = json.find('"', ks + 1);
        std::size_t vs = json.find('"', json.find(':', ke) + 1);
        std::size_t ve = json.find('"', vs + 1);
        out[json.substr(ks + 1, ke - ks - 1)] = json.substr(vs + 1, ve - vs - 1);
        i = ve + 1;
    }
    return out;
}
