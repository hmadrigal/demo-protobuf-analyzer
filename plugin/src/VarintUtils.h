#pragma once

#include <tuple>
#include <iostream>

#include <zeek/Val.h>

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		/// <summary>
		/// Decodes a varint-encoded integer from the buffer.
		/// </summary>
		std::tuple<uint64_t, uint64_t> DecodeVarint(std::vector<u_char> buffer, uint64_t offset);

	}
}