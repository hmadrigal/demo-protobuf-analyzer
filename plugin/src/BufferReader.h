#pragma once

#include <vector>
#include <iostream>
#include <iomanip>

#include <zeek/Val.h>

#include "VarintUtils.h"


namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		class BufferReader
		{

		private:
			std::vector<u_char> buffer;
			uint64_t offset;
			uint64_t savedOffset;

		protected:
			int32_t ReadInt32BE(std::vector<u_char> data, uint64_t offset);

		public:
			BufferReader(std::vector<u_char> data);

			uint64_t GetOffset();

			uint64_t LeftBytes();

			void Checkpoint(void);

			void ResetToCheckpoint(void);

			void TrySkipGrpcHeader();

			std::tuple<uint64_t, std::vector<u_char>> ReadVarint();

			std::vector<u_char> ReadBuffer(uint64_t length);
		};

	}
}