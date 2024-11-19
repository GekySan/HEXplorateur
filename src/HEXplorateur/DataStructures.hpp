#ifndef DATASTRUCTURES_HPP
#define DATASTRUCTURES_HPP

#include <string>
#include <vector>
#include <optional>

struct FileTypeInfo {
    std::string extension;
    std::string description;
    std::optional<std::string> size;
    std::optional<std::string> creationDate;
    std::optional<std::string> modificationDate;
    std::optional<std::string> md5;
    std::optional<std::string> sha1;
    std::optional<std::string> sha256;
};

struct HexSignature {
    std::vector<std::optional<unsigned char>> signature;
    std::string extension;
    std::string description;

    HexSignature(std::vector<std::optional<unsigned char>> sig, const std::string& ext, const std::string& desc)
        : signature(std::move(sig)), extension(ext), description(desc) {
    }
};

std::vector<HexSignature> getHexSignatures();

#endif