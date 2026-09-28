<h1 align="center">pubg-hyperv-memory-reader</h1>

<p align="center">
  <img src="https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square" alt="C++20">
  <img src="https://img.shields.io/badge/platform-Windows%20x64-0078D4?style=flat-square" alt="Windows x64">
  <img src="https://img.shields.io/badge/Visual%20Studio-2022-5C2D91?style=flat-square" alt="Visual Studio 2022">
  <img src="https://img.shields.io/badge/assembly-MASM-555555?style=flat-square" alt="MASM">
  <img src="https://img.shields.io/badge/protocol-Protobuf-4285F4?style=flat-square" alt="Protocol Buffers">
</p>

## 构建

安装 **Visual Studio 2022**，勾选“使用 C++ 的桌面开发”，包含 **MSVC v143** 和 **Windows SDK**。

打开 `pubg-hyperv-memory-reader.sln`，选择 **Release | x64** 并生成；或在仓库根目录的 **VS2022 Developer PowerShell** 中执行：

```powershell
msbuild .\pubg-hyperv-memory-reader.sln /m /p:Configuration=Release /p:Platform=x64
```

项目已配置 **C++20、/MT 静态运行库、关闭预编译头、启用 x64 MASM**。

- 构建产物：`bin/x64/Release/`，包含 `pubg-hyperv-memory-reader.exe` 和 `dumper.exe`。
- 中间文件：`obj/x64/Release/<项目名>/`。
