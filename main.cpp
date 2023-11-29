//
//  main.cpp
//  MachOParser
//
//  Created by apple on 2022/4/9.
//

#include <LIEF/LIEF.hpp>
#include <unistd.h>
#include "ObjCDefine.h"
#include <stdio.h>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <vector>

#define DATA_NUMS_OF_BYTE 4
#define LEFT_SHIFT_OF_DATA_STEP 8
#define DATA_POINTER_OF_BYTE 8
#define MIN(a, b) ((a <= b) ? a : b)
#define RO_POINTER_OFFSET_STRUCT (4 * DATA_POINTER_OF_BYTE)
#define PROPERTY_POINTER_OFFSET_STRUCT 64
#define NAME_POINTER_OFFSET_STRUCT 24
#define PROPERTY_LIST_ITEM_OF_BYTE 16

// 验证文件是否存在
bool isFileExists_access(const char *&name) {
    return (access(name, F_OK) != -1);
}

// 完整小端转换而来的数据
uint64_t convert_little_endian(tcb::span<const uint8_t> data, size_t len) {
    uint64_t res = 0;
    size_t limit = MIN(len, data.size());
    for (size_t i = 0; i < limit; ++i) {
        uint64_t tmp = data[i];
        res += (tmp << (LEFT_SHIFT_OF_DATA_STEP * i));
    }
    return res;
}

int main(int argc, const char * argv[]) {
    // 参数是否充足
    if (argc <= 1) {
        printf("[Error] Not enough argv !!!\n");
        return 1;
    }

    // 文件是否存在
    if (isFileExists_access(argv[1]) == false) {
        printf("[Error] No MachO file found at path: %s\n", argv[1]);
        return 1;
    }

    // 提取 arm64 架构部分来进行分析
    auto binary = LIEF::MachO::Parser::parse(argv[1], LIEF::MachO::ParserConfig::deep());
    auto arm64_bin = binary->take(LIEF::MachO::CPU_TYPES::CPU_TYPE_ARM64);
    if (arm64_bin == nullptr) {
        printf("[Error] No arm64 binary found\n");
        return 1;
    }

    // __TEXT,__objc_methname
    std::unordered_map<uint64_t, std::string> addr2methname;
    {
        LIEF::MachO::Section *objc_methname = arm64_bin->get_section("__TEXT", "__objc_methname");
        if (objc_methname == nullptr || objc_methname->segment_name() != "__TEXT") {
            printf("[Error] No __TEXT,__objc_methname inside MachO\n");
            return 1;
        }
        uint64_t methname_addr = objc_methname->address();
        auto methname_content = objc_methname->content();
        for (auto iter = methname_content.begin(); iter != methname_content.end();) {
            const char *p = (const char*)iter;
            std::string tmp_string(p);
            addr2methname[methname_addr] = tmp_string;
            auto len = strlen(p);
            iter += len + 1; // 跳过结束符
            methname_addr += len + 1;
        }
    }

    // __DATA,__objc_selrefs
    std::unordered_set<uint64_t> objc_selrefs_set;
    {
        // 获取 __DATA 段
        auto data_seg = arm64_bin->get_segment("__DATA");
        if (data_seg == nullptr) {
            printf("[Error] No __DATA inside MachO\n");
            return 1;
        }

        {
            auto objc_selrefs = data_seg->get_section("__objc_selrefs");
            if (objc_selrefs == nullptr) {
                printf("[Error] No __DATA,__objc_selrefs inside MachO\n");
                return 1;
            }
            auto selrefs_size = objc_selrefs->size();
            auto selrefs_content = objc_selrefs->content();
            for (size_t offset = 0; offset < selrefs_size; offset += DATA_POINTER_OF_BYTE) {
                auto pointer_data = selrefs_content.subspan(offset, DATA_POINTER_OF_BYTE);
                uint64_t addr = convert_little_endian(pointer_data, DATA_POINTER_OF_BYTE);
                if (addr2methname.count(addr)) {
                    // printf("%s\n", addr2methname[addr].c_str());
                    objc_selrefs_set.insert(addr);
                } else {
                    printf("cannot parse __objc_selrefs %lx\n", addr);
                }
            }
        }
    }

    // 取出没有被使用到的方法
    for (auto iter:addr2methname) {
        if (objc_selrefs_set.count(iter.first) == 0) {
            printf("%s\n", iter.second.c_str());
        }
    }

    return 0;
}
