# Runtime components

The Windows x64 runtime release bundles the installed tools used to verify DucAPK.
It contains no APKs, user analysis results, API keys, or Git credentials.

| Component | Upstream | Included form |
| --- | --- | --- |
| CPython 3.12 | https://www.python.org/ | Runtime, standard library, Tcl/Tk, ensurepip; `tools/python/LICENSE.txt` |
| Python dependencies | https://pypi.org/ | Wheels for `requirements.txt` and their dependencies; licenses remain in wheel metadata |
| .NET 10 runtime | https://github.com/dotnet/runtime | Host and shared runtime; original LICENSE and ThirdPartyNotices included |
| Il2CppDumper | https://github.com/Perfare/Il2CppDumper | Existing executable and config; MIT notice in `tools/licenses/` |
| Cpp2IL | https://github.com/SamboyCoding/Cpp2IL | Local build with DucAPK method-map output; MIT notice in `tools/licenses/` |
| JADX | https://github.com/skylot/jadx | Installed binary distribution, including upstream notices |
| Ghidra 12.1.4 | https://github.com/NationalSecurityAgency/ghidra | Original `ghidra_12.1.4_PUBLIC_20260921.zip`, including its licenses |
| Eclipse Temurin JDK 25 | https://github.com/adoptium/temurin25-binaries | Original `OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip`, including `legal/` notices |

The companion `ducapk-tool-sources-*.zip` release asset preserves Cpp2IL's source,
including the custom `DucApkMethodMapOutputFormat.cs` and plugin registration, plus
the available Il2CppDumper fork source. `provenance.json` records upstream commits.
Build artifacts and Git metadata are excluded from those source snapshots.

`runtime-manifest.json` pins asset URLs, sizes and SHA-256 checksums. The runtime
is versioned separately from source commits; Setup verifies each archive before
extracting it. Source changes do not require downloading the runtime again unless
that manifest changes or installed files are missing.
