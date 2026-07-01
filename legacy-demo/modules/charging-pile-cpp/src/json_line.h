#pragma once

#include <map>
#include <string>

std::string json_stringify(const std::map<std::string, std::string>& kv);
std::map<std::string, std::string> json_parse(const std::string& json);
