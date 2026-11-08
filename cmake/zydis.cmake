# The one Zydis pin: the DLL (through safetyhook) and tools/compat build the same decoder.
include(FetchContent)
FetchContent_Declare(
    Zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    # renovate: depName=zyantific/zydis datasource=github-tags
    GIT_TAG a2278f1d254e492f6a6b39f6cb5d1f5d515659dc # v4.1.1
    EXCLUDE_FROM_ALL
)
