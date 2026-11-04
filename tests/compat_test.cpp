// Runs only on private executable fixtures supplied to CMake; nothing is executed/hooked.
#include <windows.h>
#include <cassert>
#include <cstddef>
#include <cstring>
#include <cstdio>
#include <vector>
#include "../src/scan.h"

void flip_low_bit(uint8_t& value) {
    value=std::to_integer<uint8_t>(std::byte{value}^std::byte{1});
}

void check(const wchar_t* path, const char* build) {
    const bool patch1=std::strcmp(build,"26083076")!=0;
    HMODULE module=LoadLibraryExW(path,nullptr,DONT_RESOLVE_DLL_REFERENCES);
    assert(module);
    auto image=reinterpret_cast<const uint8_t*>(module);
    auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(image+reinterpret_cast<const IMAGE_DOS_HEADER*>(image)->e_lfanew);
    size_t size=nt->OptionalHeader.SizeOfImage;
    livemap::Targets targets;
    std::string error;
    assert(livemap::find_targets(image,targets,error));
    assert(std::strcmp(targets.build,build)==0);
    assert(targets.mining_layout==(patch1?livemap::MiningLayout::StackRecord:livemap::MiningLayout::InlineArray));
    std::vector<uint8_t> copy(image,image+size);
    auto mutable_nt=reinterpret_cast<IMAGE_NT_HEADERS64*>(copy.data()+reinterpret_cast<IMAGE_DOS_HEADER*>(copy.data())->e_lfanew);
    mutable_nt->FileHeader.TimeDateStamp=0;
    livemap::Targets rejected;
    assert(!livemap::find_targets(copy.data(),rejected,error));
    assert(error.find("unknown server build")!=std::string::npos);
    mutable_nt->FileHeader.TimeDateStamp=nt->FileHeader.TimeDateStamp;
    mutable_nt->OptionalHeader.SizeOfImage+=0x1000;
    assert(!livemap::find_targets(copy.data(),rejected,error));
    mutable_nt->OptionalHeader.SizeOfImage=nt->OptionalHeader.SizeOfImage;
    size_t table=targets.player_table-reinterpret_cast<uintptr_t>(image);
    const uintptr_t origin=reinterpret_cast<uintptr_t>(image);
    struct Site { const char* name; uintptr_t hook; size_t delta; };
    const Site required[]={{"player_table",targets.player_table,0},
        {"movement",targets.movement,0x25},{"daytime",targets.daytime,patch1?0x13u:0x12u},
        {"registry",targets.registry,0}};
    for(const auto& site:required) {
        size_t start=site.hook-origin-site.delta;
        copy[start]^=1;
        assert(!livemap::find_targets(copy.data(),rejected,error));
        assert(error.find(site.name)!=std::string::npos);
        copy[start]^=1;
    }
    if(std::strcmp(build,"26404334")==0)assert(targets.entity_table==0x830);
    if(patch1) {
        size_t accessor=targets.param_entity-origin;
        flip_low_bit(copy[accessor]);
        assert(!livemap::find_targets(copy.data(),rejected,error));
        assert(error.find("param_entity")!=std::string::npos);
        flip_low_bit(copy[accessor]);
    }
    const auto sections=IMAGE_FIRST_SECTION(mutable_nt);
    size_t text=0;
    for(WORD i=0;i<mutable_nt->FileHeader.NumberOfSections;i++)
        if(std::memcmp(sections[i].Name,".text",5)==0)text=sections[i].VirtualAddress;
    assert(text);
    auto duplicate=copy;
    std::memcpy(duplicate.data()+text+128,copy.data()+table,27);
    assert(!livemap::find_targets(duplicate.data(),rejected,error));
    assert(error.find("matched 2 times")!=std::string::npos);
    size_t mining=targets.mining-reinterpret_cast<uintptr_t>(image)-(patch1?2:0x16);
    copy[mining]^=1;
    livemap::Targets optional;
    assert(livemap::find_targets(copy.data(),optional,error));
    assert(optional.mining==0 && optional.player_table);
    FreeLibrary(module);
}
int wmain(int argc,wchar_t**argv) {
    assert(argc==3 || argc==4);
    check(argv[1],"26083076");check(argv[2],"26319703");
    if(argc==4)check(argv[3],"26404334");
    std::puts("supported builds, unknown fingerprints, corrupt/duplicate mandatory signatures and optional mining rejection passed");
}
