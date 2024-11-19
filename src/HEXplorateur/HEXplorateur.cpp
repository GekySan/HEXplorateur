#include <windows.h>
#include <commdlg.h>
#include <tchar.h>
#include <Shlwapi.h>
#include <wincrypt.h>
#include <filesystem>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <memory>
#include <wrl/client.h>

#include <d3d11.h>
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "DataStructures.hpp"

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "Shlwapi.lib")

using Microsoft::WRL::ComPtr;

constexpr std::size_t BUFFER_SIZE = 16;
constexpr std::size_t MAX_FILE_SIZE_MB = 20;
constexpr std::size_t MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

ComPtr<ID3D11Device> g_pd3dDevice = nullptr;
ComPtr<ID3D11DeviceContext> g_pd3dDeviceContext = nullptr;
ComPtr<IDXGISwapChain> g_pSwapChain = nullptr;
ComPtr<ID3D11RenderTargetView> g_mainRenderTargetView = nullptr;

std::string ByteArrayToHexString(const BYTE* byteArray, DWORD length)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase << std::setfill('0');
    for (DWORD i = 0; i < length; ++i)
    {
        oss << std::setw(2) << static_cast<int>(byteArray[i]);
    }
    return oss.str();
}

template <typename T>
T myMin(const T& a, const T& b)
{
    return (a < b) ? a : b;
}

template <typename T>
T myMax(const T& a, const T& b)
{
    return (a > b) ? a : b;
}

std::optional<std::string> CalculateFileHash(const std::string& filePath, const ALG_ID algId)
{
    HANDLE hFile = CreateFileA(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        return std::nullopt;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return std::nullopt;
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return std::nullopt;
    }

    BYTE buffer[4096];
    DWORD bytesRead = 0;

    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0)
    {
        if (!CryptHashData(hHash, buffer, bytesRead, 0))
        {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            CloseHandle(hFile);
            return std::nullopt;
        }
    }

    DWORD hashSize = 0;
    DWORD dwCount = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashSize), &dwCount, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return std::nullopt;
    }

    std::vector<BYTE> hashData(hashSize);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashData.data(), &hashSize, 0))
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return std::nullopt;
    }

    std::string hashString = ByteArrayToHexString(hashData.data(), hashSize);

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);

    return hashString;
}

std::string FormatFileTime(const FILETIME& ft)
{

    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;

    const ULONGLONG EPOCH_DIFFERENCE = 11644473600ULL;
    time_t tt = static_cast<time_t>((ull.QuadPart / 10000000ULL) - EPOCH_DIFFERENCE);

    std::tm tm;
    localtime_s(&tm, &tt);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
    return oss.str();
}

FILETIME GetFileCreationTime(const std::filesystem::path& path)
{
    HANDLE hFile = CreateFileA(
        path.string().c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {

        FILETIME ft = { 0 };
        return ft;
    }

    FILETIME ftCreate, ftAccess, ftWrite;
    if (!GetFileTime(hFile, &ftCreate, &ftAccess, &ftWrite))
    {

        FILETIME ft = { 0 };
        CloseHandle(hFile);
        return ft;
    }

    CloseHandle(hFile);
    return ftCreate;
}

std::string OpenFileDialog()
{
    OPENFILENAMEA ofn{};
    char szFile[MAX_PATH] = { 0 };

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = nullptr;
    ofn.lpstrFilter = "Tout les fichiers\0*.*\0";
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameA(&ofn))
    {
        return std::string(ofn.lpstrFile);
    }
    return "";
}

std::vector<std::string> ReadFileInHex(const std::string& filePath, std::size_t maxBytes = 0)
{
    std::ifstream file(filePath, std::ios::binary);
    std::vector<std::string> lines;

    if (!file)
        return { "Impossible d'ouvrir le fichier." };

    unsigned char buffer[BUFFER_SIZE];
    std::size_t address = 0;
    std::size_t totalBytesRead = 0;

    while ((file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE) || file.gcount() > 0) &&
        (maxBytes == 0 || totalBytesRead < maxBytes))
    {
        std::size_t bytesRead = file.gcount();

        if (maxBytes > 0 && totalBytesRead + bytesRead > maxBytes)
        {
            bytesRead = maxBytes - totalBytesRead;
        }

        std::ostringstream line;
        line << std::setw(8) << std::setfill('0') << std::hex << address << "  ";

        for (std::size_t i = 0; i < BUFFER_SIZE; ++i)
        {
            if (i < bytesRead)
                line << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buffer[i]) << " ";
            else
                line << "   ";
        }

        line << " ";
        for (std::size_t i = 0; i < bytesRead; ++i)
        {
            line << (std::isprint(buffer[i]) ? static_cast<char>(buffer[i]) : '.');
        }

        lines.emplace_back(line.str());
        address += bytesRead;
        totalBytesRead += bytesRead;

        if (maxBytes > 0 && totalBytesRead >= maxBytes)
            break;
    }
    return lines;
}

std::vector<std::string> ExtractStrings(const std::string& filePath, std::size_t minLength = 4)
{
    std::vector<std::string> strings;
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return { "Impossible d'ouvrir le fichier." };

    std::string currentString;
    char c;
    while (file.get(c))
    {
        if (std::isprint(static_cast<unsigned char>(c)) || std::isspace(static_cast<unsigned char>(c)))
        {
            currentString += c;
        }
        else
        {
            if (currentString.length() >= minLength)
            {
                strings.emplace_back(currentString);
            }
            currentString.clear();
        }
    }

    if (currentString.length() >= minLength)
    {
        strings.emplace_back(currentString);
    }

    return strings;
}

FileTypeInfo detectFileType(const std::string& filePath, const std::vector<HexSignature>& signatures)
{
    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return { "Inconnu", "Impossible d'ouvrir le fichier.", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt };

    size_t maxSignatureLength = 0;
    for (const auto& sig : signatures)
    {
        maxSignatureLength = myMax(maxSignatureLength, sig.signature.size());
    }

    std::vector<unsigned char> buffer(maxSignatureLength, 0);
    file.read(reinterpret_cast<char*>(buffer.data()), maxSignatureLength);
    std::size_t bytesRead = file.gcount();

    for (const auto& sig : signatures)
    {
        if (sig.signature.size() > bytesRead)
            continue;

        bool match = true;
        for (size_t i = 0; i < sig.signature.size(); ++i)
        {
            if (sig.signature[i].has_value() && buffer[i] != sig.signature[i].value())
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            std::filesystem::path path(filePath);
            FileTypeInfo info;
            info.extension = sig.extension;
            info.description = sig.description;

            try
            {
                std::uintmax_t size = std::filesystem::file_size(path);
                info.size = std::to_string(size) + " bytes";
            }
            catch (...)
            {
                info.size = "Inconnu";
            }

            try
            {
                FILETIME ftCreate = GetFileCreationTime(path);
                if (ftCreate.dwLowDateTime == 0 && ftCreate.dwHighDateTime == 0)
                {
                    info.creationDate = "Inconnu";
                }
                else
                {
                    info.creationDate = FormatFileTime(ftCreate);
                }
            }
            catch (...)
            {
                info.creationDate = "Inconnu";
            }

            try
            {
                auto ftimeModif = std::filesystem::last_write_time(path);

                auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                    ftimeModif - std::filesystem::file_time_type::clock::now()
                    + std::chrono::system_clock::now()
                );
                std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
                std::tm tm;
                localtime_s(&tm, &tt);
                std::ostringstream oss;
                oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
                info.modificationDate = oss.str();
            }
            catch (...)
            {
                info.modificationDate = "Inconnu";
            }

            info.md5 = CalculateFileHash(filePath, CALG_MD5);
            info.sha1 = CalculateFileHash(filePath, CALG_SHA1);
            info.sha256 = CalculateFileHash(filePath, CALG_SHA_256);
            return info;
        }
    }

    std::filesystem::path path(filePath);
    FileTypeInfo unknownInfo;
    unknownInfo.extension = "Inconnu";
    unknownInfo.description = "Type de fichier non reconnu.";

    try
    {
        std::uintmax_t size = std::filesystem::file_size(path);
        unknownInfo.size = std::to_string(size) + " bytes";
    }
    catch (...)
    {
        unknownInfo.size = "Inconnu";
    }

    try
    {
        FILETIME ftCreate = GetFileCreationTime(path);
        if (ftCreate.dwLowDateTime == 0 && ftCreate.dwHighDateTime == 0)
        {
            unknownInfo.creationDate = "Inconnu";
        }
        else
        {
            unknownInfo.creationDate = FormatFileTime(ftCreate);
        }
    }
    catch (...)
    {
        unknownInfo.creationDate = "Inconnu";
    }

    try
    {
        auto ftimeModif = std::filesystem::last_write_time(path);

        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftimeModif - std::filesystem::file_time_type::clock::now()
            + std::chrono::system_clock::now()
        );
        std::time_t tt = std::chrono::system_clock::to_time_t(sctp);
        std::tm tm;
        localtime_s(&tm, &tt);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%d-%m-%Y %H:%M:%S");
        unknownInfo.modificationDate = oss.str();
    }
    catch (...)
    {
        unknownInfo.modificationDate = "Inconnu";
    }

    unknownInfo.md5 = CalculateFileHash(filePath, CALG_MD5);
    unknownInfo.sha1 = CalculateFileHash(filePath, CALG_SHA1);
    unknownInfo.sha256 = CalculateFileHash(filePath, CALG_SHA_256);
    return unknownInfo;
}

void applyTheme()
{
    ImGuiStyle& style = ImGui::GetStyle();
    ImGui::StyleColorsDark();

    ImVec4 blue = ImVec4(7.0f / 255.0f, 68.0f / 255.0f, 220.0f / 255.0f, 1.0f);
    ImVec4 blueHovered = ImVec4(10.0f / 255.0f, 80.0f / 255.0f, 240.0f / 255.0f, 1.0f);
    ImVec4 blueActive = ImVec4(5.0f / 255.0f, 50.0f / 255.0f, 200.0f / 255.0f, 1.0f);

    style.Colors[ImGuiCol_Header] = blue;
    style.Colors[ImGuiCol_HeaderHovered] = blueHovered;
    style.Colors[ImGuiCol_HeaderActive] = blueActive;

    style.Colors[ImGuiCol_Button] = blue;
    style.Colors[ImGuiCol_ButtonHovered] = blueHovered;
    style.Colors[ImGuiCol_ButtonActive] = blueActive;

    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.7f, 0.7f, 0.7f, 0.3f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.8f, 0.8f, 0.8f, 0.4f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.9f, 0.9f, 0.9f, 0.5f);

    style.Colors[ImGuiCol_ScrollbarGrab] = blue;
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = blueHovered;
    style.Colors[ImGuiCol_ScrollbarGrabActive] = blueActive;

    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.1f, 0.1f, 0.1f, 1.0f);

    style.Colors[ImGuiCol_Tab] = blue;
    style.Colors[ImGuiCol_TabHovered] = blueHovered;
    style.Colors[ImGuiCol_TabActive] = blueActive;
    style.Colors[ImGuiCol_TabUnfocused] = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
    style.Colors[ImGuiCol_TabUnfocusedActive] = ImVec4(0.6f, 0.6f, 0.6f, 1.0f);
}

std::string GetExecutableDirectory()
{
    char path[MAX_PATH] = { 0 };
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0)
    {
        return "";
    }

    if (!PathRemoveFileSpecA(path))
    {
        return "";
    }

    return std::string(path) + "\\";
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 1;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL featureLevel;
    std::vector<D3D_FEATURE_LEVEL> featureLevels = {
        D3D_FEATURE_LEVEL_11_0,
        D3D_FEATURE_LEVEL_10_1,
        D3D_FEATURE_LEVEL_10_0,
    };

    HRESULT res = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        featureLevels.data(),
        static_cast<UINT>(featureLevels.size()),
        D3D11_SDK_VERSION,
        &sd,
        &g_pSwapChain,
        &g_pd3dDevice,
        &featureLevel,
        &g_pd3dDeviceContext
    );

    if (FAILED(res))
        return false;

    ComPtr<ID3D11Texture2D> pBackBuffer;
    res = g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), &pBackBuffer);
    if (FAILED(res))
        return false;

    res = g_pd3dDevice->CreateRenderTargetView(pBackBuffer.Get(), nullptr, &g_mainRenderTargetView);
    if (FAILED(res))
        return false;

    return true;
}

void CleanupDeviceD3D()
{
    g_mainRenderTargetView.Reset();
    g_pSwapChain.Reset();
    g_pd3dDeviceContext.Reset();
    g_pd3dDevice.Reset();
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return TRUE;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED)
        {
            g_pSwapChain->ResizeBuffers(0, LOWORD(lParam), HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            g_mainRenderTargetView.Reset();

            ComPtr<ID3D11Texture2D> pBackBuffer;
            if (SUCCEEDED(g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), &pBackBuffer)))
            {
                g_pd3dDevice->CreateRenderTargetView(pBackBuffer.Get(), nullptr, &g_mainRenderTargetView);
            }
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
            return 0;
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}

int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd)
{

    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, WndProc, 0L, 0L, hInstance, nullptr, nullptr, nullptr, nullptr, _T("HexViewer"), nullptr };
    RegisterClassEx(&wc);

    HWND hwnd = CreateWindow(
        wc.lpszClassName,
        _T("HEXplorateur"),
        WS_OVERLAPPEDWINDOW & ~WS_MAXIMIZEBOX & ~WS_THICKFRAME,
        (GetSystemMetrics(SM_CXSCREEN) - 1000) / 2,
        (GetSystemMetrics(SM_CYSCREEN) - 800) / 2,
        1000, 800,
        nullptr, nullptr, wc.hInstance, nullptr
    );

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        UnregisterClass(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ShowWindow(hwnd, SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    io.IniFilename = nullptr;

    applyTheme();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice.Get(), g_pd3dDeviceContext.Get());

    std::vector<HexSignature> hexSignatures = getHexSignatures();

    std::string selectedFilePath;
    std::vector<std::string> hexContent;
    std::vector<std::string> extractedStrings;
    FileTypeInfo fileTypeInfo = { "Inconnu", "Aucune détection effectuée.", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt };

    std::size_t bytesToDisplay = 2048;
    std::size_t fileSize = 0;

    std::string errorMessage;
    bool showErrorPopup = false;

    MSG msg;
    ZeroMemory(&msg, sizeof(msg));
    while (msg.message != WM_QUIT)
    {

        if (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (showErrorPopup)
        {
            ImGui::SetNextWindowSize(ImVec2(500, 0), ImGuiCond_FirstUseEver);
            ImGui::OpenPopup("Erreur");
        }

        if (ImGui::BeginPopupModal("Erreur", nullptr, ImGuiWindowFlags_AlwaysAutoResize))
        {
            ImGui::TextWrapped("%s", errorMessage.c_str());
            ImGui::Separator();

            float windowWidth = ImGui::GetWindowSize().x;
            float buttonWidth = 120.0f;
            float centerOffset = (windowWidth - buttonWidth) / 2.0f;

            ImGui::SetCursorPosX(centerOffset);

            if (ImGui::Button("OK", ImVec2(buttonWidth, 0)))
            {
                ImGui::CloseCurrentPopup();
                showErrorPopup = false;
                errorMessage.clear();
            }
            ImGui::SetItemDefaultFocus();
            ImGui::EndPopup();
        }

        ImGui::SetNextWindowSize(ImVec2(1000, 800));
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::Begin("HEXplorateur", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoTitleBar);

        if (ImGui::Button("Ouvrir un fichier"))
        {
            selectedFilePath = OpenFileDialog();
            if (!selectedFilePath.empty())
            {
                try
                {
                    fileSize = std::filesystem::file_size(selectedFilePath);
                }
                catch (const std::filesystem::filesystem_error&)
                {
                    fileSize = 0;
                }

                if (fileSize > MAX_FILE_SIZE_BYTES)
                {
                    errorMessage = "Le fichier dépasse la taille maximale de " + std::to_string(MAX_FILE_SIZE_MB) + " Mo.";
                    showErrorPopup = true;

                    selectedFilePath.clear();
                    hexContent.clear();
                    fileTypeInfo = FileTypeInfo();
                    extractedStrings.clear();
                }
                else
                {

                    if (fileSize < bytesToDisplay)
                        bytesToDisplay = (fileSize >= 1) ? fileSize : 1;

                    hexContent = ReadFileInHex(selectedFilePath, bytesToDisplay);
                    fileTypeInfo = detectFileType(selectedFilePath, hexSignatures);
                    extractedStrings = ExtractStrings(selectedFilePath);
                }
            }
        }

        ImGui::Separator();

        if (!selectedFilePath.empty())
        {
            if (ImGui::BeginTabBar("MyTabBar", ImGuiTabBarFlags_None))
            {

                if (ImGui::BeginTabItem("Infos"))
                {
                    if (ImGui::BeginTable("FileInfoTable", 2, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_NoBordersInBody))
                    {

                        auto addRow = [&](const char* label, const std::optional<std::string>& value) {

                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::PushItemWidth(150.0f);
                            ImGui::TextUnformatted(label);
                            ImGui::TableSetColumnIndex(1);
                            if (value.has_value())
                                ImGui::TextUnformatted(value->c_str());
                            else
                                ImGui::TextUnformatted("N/A");
                            };

                        addRow("Fichier", selectedFilePath.empty() ? std::nullopt : std::optional<std::string>(selectedFilePath));
                        addRow("Type de fichier", (fileTypeInfo.extension.empty() && fileTypeInfo.description.empty()) ? std::nullopt : std::optional<std::string>(fileTypeInfo.extension + (!fileTypeInfo.extension.empty() && !fileTypeInfo.description.empty() ? " | " : "") + fileTypeInfo.description));
                        addRow("Taille", fileTypeInfo.size);
                        addRow("Date de création", fileTypeInfo.creationDate);
                        addRow("Date de modification", fileTypeInfo.modificationDate);
                        addRow("MD5", fileTypeInfo.md5);
                        addRow("SHA1", fileTypeInfo.sha1);
                        addRow("SHA256", fileTypeInfo.sha256);

                        ImGui::EndTable();
                    }

                    if (ImGui::Button("Copier les hashs"))
                    {
                        std::ostringstream copyStr;
                        copyStr << "MD5: " << (fileTypeInfo.md5.has_value() ? fileTypeInfo.md5.value() : "N/A") << "\n";
                        copyStr << "SHA1: " << (fileTypeInfo.sha1.has_value() ? fileTypeInfo.sha1.value() : "N/A") << "\n";
                        copyStr << "SHA256: " << (fileTypeInfo.sha256.has_value() ? fileTypeInfo.sha256.value() : "N/A") << "\n";

                        ImGui::SetClipboardText(copyStr.str().c_str());
                    }

                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Hex"))
                {
                    ImGui::Text("Nombre de bytes à afficher :");
                    ImGui::SameLine();

                    int bytesInput = static_cast<int>(bytesToDisplay);
                    bool bytesChanged = false;
                    if (ImGui::InputInt("##BytesToDisplay", &bytesInput, 1, 1, ImGuiInputTextFlags_CharsDecimal))
                    {
                        std::size_t newBytes = static_cast<std::size_t>(bytesInput);

                        if (newBytes < 1)
                            newBytes = 1;
                        if (newBytes > fileSize)
                            newBytes = fileSize;

                        if (newBytes != bytesToDisplay)
                        {
                            bytesToDisplay = newBytes;
                            bytesChanged = true;
                        }
                    }

                    ImGui::TextWrapped("Maximum : %zu bytes", fileSize);

                    if (bytesChanged)
                    {
                        hexContent = ReadFileInHex(selectedFilePath, bytesToDisplay);
                    }

                    ImGui::Separator();

                    ImGui::BeginChild("Hex", ImVec2(-10, 600), true, ImGuiWindowFlags_HorizontalScrollbar);
                    ImGui::TextUnformatted("Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  ASCII");
                    ImGui::Separator();

                    for (const auto& line : hexContent)
                    {
                        ImGui::TextUnformatted(line.c_str());
                    }
                    ImGui::EndChild();

                    ImGui::EndTabItem();
                }

                if (ImGui::BeginTabItem("Strings"))
                {
                    ImGui::BeginChild("StringsViewer", ImVec2(-10, 600), true, ImGuiWindowFlags_HorizontalScrollbar);

                    ImGui::Text("Filtre");
                    ImGui::SameLine();
                    static char filterBuffer[128] = "";
                    ImGui::InputText("##Filtre", filterBuffer, IM_ARRAYSIZE(filterBuffer));

                    static bool respectCase = true;
                    ImGui::Checkbox("Respecter la casse", &respectCase);

                    auto contains = [&](const std::string& str, const std::string& substr, bool caseSensitive) -> bool {
                        if (substr.empty()) return true;
                        if (caseSensitive)
                        {
                            return str.find(substr) != std::string::npos;
                        }
                        else
                        {
                            std::string strLower = str;
                            std::string substrLower = substr;
                            std::transform(strLower.begin(), strLower.end(), strLower.begin(), ::tolower);
                            std::transform(substrLower.begin(), substrLower.end(), substrLower.begin(), ::tolower);
                            return strLower.find(substrLower) != std::string::npos;
                        }
                        };

                    for (const auto& str : extractedStrings)
                    {
                        if (contains(str, filterBuffer, respectCase))
                        {
                            ImGui::TextUnformatted(str.c_str());
                        }
                    }

                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }

                ImGui::EndTabBar();
            }
        }
        else
        {
            ImGui::Text("Aucun fichier sélectionné.");
        }

        ImGui::End();

        ImGui::Render();
        const float clear_color[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, g_mainRenderTargetView.GetAddressOf(), nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView.Get(), clear_color);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClass(wc.lpszClassName, wc.hInstance);

    return 0;
}