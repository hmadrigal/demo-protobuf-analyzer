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



namespace Pipoca {
namespace Protobuf {

/// <summary>
/// A struct that represents a part of a protobuf message.
/// </summary>
typedef struct
	{
	uint64_t byteRangeStart;
	uint64_t byteRangeEnd;
	uint64_t index;
	uint64_t type;
	std::vector<u_char> value;

	} ProtobufPart;

/// <summary>
/// A enum that represents the different types of a protobuf message.
/// </summary>
enum TYPES
	{
	VARINT = 0,
	FIXED64 = 1,
	LENDELIM = 2,
	FIXED32 = 5
	};

/// <summary>
/// A class that decodes a protobuf message.
/// </summary>
class ProtobufDecoder
	{

public:

	/// <summary>
	/// Constructor.
	/// </summary>
	ProtobufDecoder(zeek::file_analysis::File* file);

	/// <summary>
	/// Decodes a buffer that contains a protobuf message.
	/// </summary>
	std::tuple<std::vector<ProtobufPart>, std::vector<u_char>>
	DecodeProto(std::vector<u_char> data);

	/// <summary>
	/// Decodes a part of a protobuf message.
	/// </summary>
	void DecodeProtobufPart(ProtobufPart part);

	/// <summary>
	/// Decodes several parts of a protobuf message.
	/// </summary>
	bool DecodeProto(std::vector<ProtobufPart> parts);

private:
	zeek::file_analysis::File* file;


};
}
}