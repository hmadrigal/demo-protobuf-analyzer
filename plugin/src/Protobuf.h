#pragma once

#include <zeek/Event.h>
#include <zeek/Val.h>
#include <zeek/ZeekString.h>
#include <zeek/file_analysis/Analyzer.h>
#include <zeek/file_analysis/Component.h>
#include <zeek/file_analysis/File.h>
#include <zeek/file_analysis/Manager.h>
#include <zeek/DebugLogger.h>

#include <iostream>
#include <iomanip>

#include <tuple>
#include <vector>

#include "BufferReader.h"
#include "events.bif.h"



namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

typedef struct
	{
	uint64_t byteRangeStart;
	uint64_t byteRangeEnd;
	uint64_t index;
	uint64_t type;
	std::vector<u_char> value;

	} ProtobufPart;

enum TYPES
	{
	VARINT = 0,
	FIXED64 = 1,
	LENDELIM = 2,
	FIXED32 = 5
	};

class Protobuf : public zeek::file_analysis::Analyzer
	{
public:
	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args,
	                                                  zeek::file_analysis::File* file);

	bool DeliverStream(const u_char* data, uint64_t len) override;

	bool EndOfFile() override;

	std::tuple<std::vector<ProtobufPart>, std::vector<u_char>>
	DecodeProto(std::vector<u_char> data);
	void DecodeProtobufPart(ProtobufPart part);

	bool ProtobufDisplay(std::vector<ProtobufPart> parts);

protected:
	Protobuf(zeek::RecordValPtr args, zeek::file_analysis::File* file);

private:
	std::vector<u_char> buffer;
	};
	}
	}