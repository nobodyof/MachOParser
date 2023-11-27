//
//  ObjCDefine.h
//  MachOParser
//
//  Created by apple on 2022/4/13.
//

#ifndef ObjCDefine_h
#define ObjCDefine_h


namespace ObjCMachO {
/*
    struct objc_ivar {
        char *ivar_name;
        char *ivar_type;
        int ivar_offset;
    };

    struct objc_ivar_list {
        int ivar_count;
    //    struct objc_ivar list[count];
        struct objc_ivar *list;
    };

    struct objc_class {
        uint64_t isa;
        uint64_t superclass;
        uint64_t cache;
        uint64_t vtable;
        uint64_t data; // points to class_ro_t
    };
*/

// https://opensource.apple.com/source/objc4/objc4-551.1/runtime/objc-runtime-new.h.auto.html
// Values for class_ro_t->flags
// These are emitted by the compiler and are part of the ABI.
// class is a metaclass
#define RO_META               (1<<0)
// class is a root class
#define RO_ROOT               (1<<1)
// class has .cxx_construct/destruct implementations
#define RO_HAS_CXX_STRUCTORS  (1<<2)
// class has +load implementation
// #define RO_HAS_LOAD_METHOD    (1<<3)
// class has visibility=hidden set
#define RO_HIDDEN             (1<<4)
// class has attribute(objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak
#define RO_EXCEPTION          (1<<5)
// this bit is available for reassignment
// #define RO_REUSE_ME           (1<<6)
// class compiled with -fobjc-arc (automatic retain/release)
#define RO_IS_ARR             (1<<7)
// class has .cxx_destruct but no .cxx_construct (with RO_HAS_CXX_STRUCTORS)
#define RO_HAS_CXX_DTOR_ONLY  (1<<8)

// class is in an unloadable bundle - must never be set by compiler
#define RO_FROM_BUNDLE        (1<<29)
// class is unrealized future class - must never be set by compiler
#define RO_FUTURE             (1<<30)
// class is realized - must never be set by compiler
#define RO_REALIZED           (1<<31)


// Values for class_rw_t->flags
// These are not emitted by the compiler and are never used in class_ro_t.
// Their presence should be considered in future ABI versions.
// class_t->data is class_rw_t, not class_ro_t
#define RW_REALIZED           (1<<31)
// class is unresolved future class
#define RW_FUTURE             (1<<30)
// class is initialized
#define RW_INITIALIZED        (1<<29)
// class is initializing
#define RW_INITIALIZING       (1<<28)
// class_rw_t->ro is heap copy of class_ro_t
#define RW_COPIED_RO          (1<<27)
// class allocated but not yet registered
#define RW_CONSTRUCTING       (1<<26)
// class allocated and registered
#define RW_CONSTRUCTED        (1<<25)
// GC:  class has unsafe finalize method
#define RW_FINALIZE_ON_MAIN_THREAD (1<<24)
// class +load has been called
#define RW_LOADED             (1<<23)
// class does not share super's vtable
#define RW_SPECIALIZED_VTABLE (1<<22)
// class instances may have associative references
#define RW_INSTANCES_HAVE_ASSOCIATED_OBJECTS (1<<21)
// class or superclass has .cxx_construct implementation
#define RW_HAS_CXX_CTOR       (1<<20)
// class or superclass has .cxx_destruct implementation
#define RW_HAS_CXX_DTOR       (1<<19)
// class has instance-specific GC layout
#define RW_HAS_INSTANCE_SPECIFIC_LAYOUT (1 << 18)
// class's method list is an array of method lists
#define RW_METHOD_ARRAY       (1<<17)
// class or superclass has custom allocWithZone: implementation
#define RW_HAS_CUSTOM_AWZ     (1<<16)
// class or superclass has custom retain/release/autorelease/retainCount
#define RW_HAS_CUSTOM_RR   (1<<15)
};
 

#endif /* ObjCDefine_h */
