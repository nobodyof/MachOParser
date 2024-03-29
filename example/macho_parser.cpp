//
//  main.cpp
//  MachOParser
//
//  Created by apple on 2022/4/9.
//

#include <LIEF/LIEF.hpp>
#include <unistd.h>
#include "ObjCDefine.h"
//#import <stdio.h>
//#import <unordered_map>
//#import <string.h>
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

    // 解析出每一个类名，map[addr] = classname
    std::unordered_map<uint64_t, std::string> addr2classname;
    {
        // 获取 __TEXT,__objc_classname 段
        auto classname_section = arm64_bin->get_section("__objc_classname");
        if (classname_section == nullptr || classname_section->segment_name() != "__TEXT") {
            printf("[Error] No __TEXT,__objc_classname inside MachO\n");
            return 1;
        }
        // 解析 __objc_classname 段，里面存的是类名字符串，以 \0 划分
        uint64_t classname_addr = classname_section->address();
        printf("__TEXT,__objc_classname section address: 0x%llx\n", classname_addr);
        
        auto classname_content = classname_section->content();
        for (auto iter = classname_content.begin(); iter != classname_content.end();) {
            const char *p = (const char*)iter;
            std::string tmp_string(p);
//            printf("string: %s - 0x%llx\n", tmp_string.c_str(), classname_addr);
            addr2classname[classname_addr] = tmp_string;
            auto len = strlen(p);
            iter += len + 1; // 跳过结束符
            classname_addr += len + 1;
        }
    }

    // __TEXT,__objc_methname/__TEXT,__cstring
    std::unordered_map<uint64_t, std::string> addr2methname;
    {
        {
            LIEF::MachO::Section *objc_methname = arm64_bin->get_section("__objc_methname");
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
        {
            LIEF::MachO::Section *cstring = arm64_bin->get_section("__cstring");
            if (cstring == nullptr || cstring->segment_name() != "__TEXT") {
                printf("[Error] No __TEXT,__cstring inside MachO\n");
                return 1;
            }
            uint64_t cstring_addr = cstring->address();
            auto cstring_content = cstring->content();
            for (auto iter = cstring_content.begin(); iter != cstring_content.end();) {
                const char *p = (const char*)iter;
                std::string tmp_string(p);
                addr2methname[cstring_addr] = tmp_string;
                auto len = strlen(p);
                iter += len + 1; // 跳过结束符
                cstring_addr += len + 1;
            }
        }
    }
    
    // __DATA section
    LIEF::MachO::Section *objc_data_sec = nullptr;
    LIEF::MachO::Section *objc_const_sec = nullptr;
    LIEF::MachO::Section *objc_classlist_sec = nullptr;
    LIEF::MachO::Section *data_sec = nullptr;
    uint64_t maximun_limit = UINT64_MAX;
    {
        // 获取 __DATA 段
        auto data_seg = arm64_bin->get_segment("__DATA");
        if (data_seg == nullptr) {
            printf("[Error] No __DATA inside MachO\n");
            return 1;
        }
        maximun_limit = data_seg->virtual_address() + data_seg->virtual_size();
        // 遍历 section
        auto it_section = data_seg->sections();
        for (auto section = it_section.begin(); section != it_section.end(); ++section) {
//            printf("%s\n", section->fullname().c_str());
            if (section->name() == "__objc_ivar") { // __objc_ivar
                // 存储了所有 ivar 的地方，一个大小为 4 字节
                auto content = section->content();
                printf("total ivar nums: %lu\n", content.size() / DATA_NUMS_OF_BYTE);
            } else if (section->name() == "__objc_data") { // __objc_data
                objc_data_sec = &(*section);
            } else if (section->name() == "__objc_const") { // __objc_const
                objc_const_sec = &(*section);
            } else if (section->name() == "__objc_classlist") { // __objc_classlist
                objc_classlist_sec = &(*section);
            } else if (section->name() == "__data") { // __data
                data_sec = &(*section);
            }
        }
    }
    
    // 类 ro/rw 在 __objc_const 的地址
    std::vector<uint64_t> classro_addr_list;
    std::vector<uint64_t> classrw_addr_list;
    {
        // 解析 __objc_classlist 段，找到类在 __objc_data/__data 的地址
        // 里面存的是指向每一个类信息的指针，大小为 8 字节
        std::vector<uint64_t> class_addr_list;
        auto objc_classlist_content = objc_classlist_sec->content();
        auto objc_classlist_size = objc_classlist_content.size();
        printf("total class nums: %lu\n", objc_classlist_size / DATA_POINTER_OF_BYTE);
        for (size_t offset = 0; offset < objc_classlist_size; offset += DATA_POINTER_OF_BYTE) {
            auto pointer_data = objc_classlist_content.subspan(offset, DATA_POINTER_OF_BYTE);
            class_addr_list.push_back(convert_little_endian(pointer_data, DATA_POINTER_OF_BYTE));
        }
        
        // 解析 __objc_data 段，找到类 ro 在 __objc_const 的地址
        // 解析 __data 段，找到类 rw 在 __data 的地址
        auto objc_data_content = objc_data_sec->content();
        auto objc_data_base_addr = objc_data_sec->address();
        auto data_content = data_sec->content();
        auto data_base_addr = data_sec->address();
        auto data_end_addr = data_base_addr + data_sec->size();
        for (auto addr : class_addr_list) { // 解析 __objc_classlist 的指针指向
            if (addr < data_base_addr) { // ro, __DATA,__objc_data
                auto offset = addr - objc_data_base_addr + RO_POINTER_OFFSET_STRUCT;
                auto pointer_data = objc_data_content.subspan(offset, DATA_POINTER_OF_BYTE);
                classro_addr_list.push_back(convert_little_endian(pointer_data, DATA_POINTER_OF_BYTE));
            } else if (addr < data_end_addr) { // rw, __DATA,__data
                auto offset = addr - data_base_addr + RO_POINTER_OFFSET_STRUCT;
                auto pointer_data = data_content.subspan(offset, DATA_POINTER_OF_BYTE);
                classrw_addr_list.push_back(convert_little_endian(pointer_data, DATA_POINTER_OF_BYTE));
            } else {
                printf("strange address of __objc_classlist: %llx\n", addr);
                abort();
            }
        }
    }
    std::sort(classro_addr_list.begin(), classro_addr_list.end());
    printf("__DATA,__objc_classlist, ro nums: %lu, rw nums: %lu\n", classro_addr_list.size(), classrw_addr_list.size());
    
    // 解析 property
    uint64_t total_prop_nums = 0;
    {
        // __objc_const / __objc_data
        auto objc_const_content = objc_const_sec->content();
        auto objc_const_base_addr = objc_const_sec->address();
        auto objc_data_content = objc_data_sec->content();
        auto objc_data_base_addr = objc_data_sec->address();
        auto objc_data_end_addr = objc_data_base_addr + objc_data_sec->size();
        uint64_t minimun_limit = (1llu << 32); // 前 4GB 为 page zero
        for (auto addr : classro_addr_list) {
            /*
             __objc_data(class):
                 ISA - 8B
                 Super Class - 8B
                 Cache - 8B
                 Vtable - 8B
                 Data - 8B - 指向 __objc_const/__objc_data 的指针

             __objc_const/__objc_data(class info):
                Flags - 4B
                Instance Start - 4B
                Instance Size - 4B
                Reserved - 4B
                Instance Var Layout - 8B - 指向 __objc_classname 的数据，
                                    代表 OC 的 GC 对于 strong 和 weak 的 ivars 的一个 bitmap 的 layout(布局)描述
                Name - 8B - 指向 __objc_classname 类名的指针
                Base Methods - 8B - 指向 method list 的指针
                Base Protocols - 8B
                Instance Variables - 8B - 指向 Variable List 的指针，数据里面 Offset 指向 __objc_ivar
                Weak Instance Var Layout - 8B
                Base Properties - 8B - 指向 property list 的指针

             property list:
                Entry Size - 4B
                Count - 4B
                Name - 8B
                Attributes - 8B
             */
            uint64_t property_ptr = 0;
            uint64_t classname_ptr = 0;
            if (addr < objc_data_base_addr) { // __objc_const
                auto name_offset = addr - objc_const_base_addr + NAME_POINTER_OFFSET_STRUCT;
                classname_ptr = convert_little_endian(objc_const_content.subspan(name_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
                
                auto property_offset = addr - objc_const_base_addr + PROPERTY_POINTER_OFFSET_STRUCT;
                property_ptr = convert_little_endian(objc_const_content.subspan(property_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
            } else if (addr < objc_data_end_addr) { // __objc_data
                auto data_ptr_offset = addr - objc_data_base_addr + RO_POINTER_OFFSET_STRUCT;
                auto data_ptr = convert_little_endian(objc_data_content.subspan(data_ptr_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
                // 属于指向同一个数据的类
                if (std::binary_search(classro_addr_list.begin(), classro_addr_list.end(), data_ptr)) {
//                if (std::find(classro_addr_list.begin(), classro_addr_list.end(), data_ptr) != classro_addr_list.end()) {
                    continue;
                }
                // 还有可能是无法解析的 rw 数据，在运行时才会补全地址
//                printf("data_ptr: %llx\n", data_ptr);
                if (data_ptr <= minimun_limit || data_ptr > maximun_limit) {
                    continue;
                }
            } else {
                abort();
            }
            assert(classname_ptr != 0);
            assert(addr2classname.find(classname_ptr) != addr2classname.end());
            
            if (property_ptr == 0) {
                printf("\nclass: %s, prop nums: 0\n", addr2classname[classname_ptr].c_str());
                continue;
            }
            
            auto prop_list_offset = property_ptr - objc_const_base_addr + DATA_NUMS_OF_BYTE;
            auto property_count = convert_little_endian(objc_const_content.subspan(prop_list_offset, DATA_NUMS_OF_BYTE), DATA_NUMS_OF_BYTE);
            printf("\nclass: %s, prop nums: %llu\n", addr2classname[classname_ptr].c_str(), property_count);
            total_prop_nums += property_count;

            // 解析出所有的 property
            for (int i = 0; i < property_count; ++i) {
                auto cur_offset = prop_list_offset + DATA_NUMS_OF_BYTE + (PROPERTY_LIST_ITEM_OF_BYTE * i);
                auto property_name_addr = convert_little_endian(objc_const_content.subspan(cur_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
                auto property_attribute_addr = convert_little_endian(objc_const_content.subspan(cur_offset + DATA_POINTER_OF_BYTE, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);

                assert(property_name_addr != 0);
                assert(addr2methname.find(property_name_addr) != addr2methname.end());
                assert(property_attribute_addr != 0);
                assert(addr2methname.find(property_attribute_addr) != addr2methname.end());

                printf("Name: %s, Attribute: %s\n", addr2methname[property_name_addr].c_str(), addr2methname[property_attribute_addr].c_str());
            }
        }
        // 没啥用，rw 全是运行时补全的信息
//        // rw，复制一遍
//        for (auto addr : classrw_addr_list) {
//            uint64_t property_ptr = 0;
//            uint64_t classname_ptr = 0;
//            if (addr < objc_data_base_addr) { // __objc_const
//                auto name_offset = addr - objc_const_base_addr + NAME_POINTER_OFFSET_STRUCT;
//                classname_ptr = convert_little_endian(objc_const_content.subspan(name_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
//
//                auto property_offset = addr - objc_const_base_addr + PROPERTY_POINTER_OFFSET_STRUCT;
//                property_ptr = convert_little_endian(objc_const_content.subspan(property_offset, DATA_POINTER_OF_BYTE), DATA_POINTER_OF_BYTE);
//            } else {
//                abort();
//            }
//            if (property_ptr <= minimun_limit || property_ptr > maximun_limit) {
//                continue;
//            }
//            assert(classname_ptr == 0 || addr2classname.find(classname_ptr) != addr2classname.end());
//
//            if (property_ptr == 0) {
//                printf("class: %s, prop nums: 0\n", addr2classname[classname_ptr].c_str());
//                continue;
//            }
//
//            auto prop_list_offset = property_ptr - objc_const_base_addr + DATA_NUMS_OF_BYTE;
//            auto property_count = convert_little_endian(objc_const_content.subspan(prop_list_offset, DATA_NUMS_OF_BYTE), DATA_NUMS_OF_BYTE);
//            printf("class: %s, prop nums: %llu\n", addr2classname[classname_ptr].c_str(), property_count);
//            total_prop_nums += property_count;
//        }
    }
    printf("\ntotal custom class prop nums: %llu\n", total_prop_nums);
    return 0;
}
