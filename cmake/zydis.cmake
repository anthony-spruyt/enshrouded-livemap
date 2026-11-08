# The one Zydis pin: the DLL (through safetyhook) and tools/compat build the same decoder.
include(FetchContent)
FetchContent_Declare(
    Zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    # renovate: depName=zyantific/zydis datasource=github-tags
    GIT_TAG 569320ad3c4856da13b9dbf1f0d9e20bda63870e # v4.1.0
    EXCLUDE_FROM_ALL
)
