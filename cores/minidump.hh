#pragma once

#include <utility>
#include <cstdint>

#include "core.hh"

namespace cores {

  namespace MINIDUMP {
    using ULONG32 = uint32_t;
    using ULONG64 = uint64_t;
    using RVA = ULONG32;
    using RVA64 = ULONG64;

    typedef struct {
      ULONG32 Signature;
      ULONG32 Version;
      ULONG32 NumberOfStreams;
      RVA     StreamDirectoryRva;
      ULONG32 CheckSum;
      union {
	ULONG32 Reserved;
	ULONG32 TimeDateStamp;
      };
      ULONG64 Flags;
    } HEADER;

    typedef struct {
      ULONG32 DataSize;
      RVA     Rva;
    } LOCATION_DESCRIPTOR;

    typedef struct {
      ULONG32                      StreamType;
      LOCATION_DESCRIPTOR Location;
    } DIRECTORY;

    constexpr ULONG32 SIGNATURE = 0x504d444d; // 'PMDM'

    typedef enum STREAM_TYPE {
      UnusedStream,
      ReservedStream0,
      ReservedStream1,
      ThreadListStream,
      ModuleListStream,
      MemoryListStream,
      ExceptionStream,
      SystemInfoStream,
      ThreadExListStream,
      Memory64ListStream,
      CommentStreamA,
      CommentStreamW,
      HandleDataStream,
      FunctionTableStream,
      UnloadedModuleListStream,
      MiscInfoStream,
      MemoryInfoListStream,
      ThreadInfoListStream,
      HandleOperationListStream,
      TokenStream,
      JavaScriptDataStream,
      SystemMemoryInfoStream,
      ProcessVmCountersStream,
      IptTraceStream,
      ThreadNamesStream,
      ceStreamNull,
      ceStreamSystemInfo,
      ceStreamException,
      ceStreamModuleList,
      ceStreamProcessList,
      ceStreamThreadList,
      ceStreamThreadContextList,
      ceStreamThreadCallStackList,
      ceStreamMemoryVirtualList,
      ceStreamMemoryPhysicalList,
      ceStreamBucketParameters,
      ceStreamProcessModuleMap,
      ceStreamDiagnosisList,
      LastReservedStream
    } STREAM_TYPE;

    typedef struct {
      ULONG64                      StartOfMemoryRange;
      LOCATION_DESCRIPTOR Memory;
    } MEMORY_DESCRIPTOR;
    typedef MEMORY_DESCRIPTOR MEMORY_DESCRIPTOR64;
  
    typedef struct {
      ULONG32                    NumberOfMemoryRanges;
      MEMORY_DESCRIPTOR MemoryRanges[0];
    } MEMORY_LIST;

    typedef struct {
      ULONG64                      NumberOfMemoryRanges;
      RVA64                        BaseRva;
      MEMORY_DESCRIPTOR64 MemoryRanges[0];
    } MEMORY64_LIST;
  
  }

  class Minidump: public Core {
  public:
    template <typename... Args>
    Minidump(Args&&... args): Core(std::forward<Args>(args)...) {}

    virtual void parse() override;

    static Core *Create(const char *path) {
      return new Minidump(path);
    }
  
  private:
    template <typename T>
    const T *at_loc(const MINIDUMP::LOCATION_DESCRIPTOR& loc) {
      return at<T>((size_t) loc.Rva);
    }

    template <typename T>
    void parse_memory_list(const MINIDUMP::LOCATION_DESCRIPTOR& loc);
  };

}
