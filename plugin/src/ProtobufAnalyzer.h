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

#include "ProtobufDecoder.h"
#include "BufferReader.h"
#include "events.bif.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

class ProtobufAnalyzer : public zeek::file_analysis::Analyzer
	{
public:
	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args,
	                                                  zeek::file_analysis::File* file);

	bool DeliverStream(const u_char* data, uint64_t len) override;

	bool EndOfFile() override;

protected:
	ProtobufAnalyzer(zeek::RecordValPtr args, zeek::file_analysis::File* file);

private:
	std::vector<u_char> buffer;

};
}
}