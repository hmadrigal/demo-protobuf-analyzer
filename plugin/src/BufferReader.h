#pragma once

#include <vector>
#include <iostream>
#include <iomanip>

#include <zeek/Val.h>

#include "VarintUtils.h"


namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		/// <summary>
		/// Receives a buffer as paramters, and provides methods to read data from it.
		/// </summary>
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

			/// <summary>
			/// Get the current offset of the reader.
			/// </summary>
			uint64_t GetOffset();

			/// <summary>
			/// Returns the number of bytes left in the buffer.
			/// </summary>
			uint64_t LeftBytes();

			/// <summary>
			/// Sets a checkpoint to the current offset.
			/// </summary>
			void Checkpoint(void);

			/// <summary>
			/// Resets the offset to the last checkpoint.
			/// </summary>
			void ResetToCheckpoint(void);

			/// <summary>
			/// Tries to skip the gRPC header. Some gRPC messages have a header that we need to skip.
			void TrySkipGrpcHeader();

			/// <summary>
			/// Reads a Varint from the buffer.
			std::tuple<uint64_t, std::vector<u_char>> ReadVarint();

			/// <summary>
			/// Reads a byte from the buffer.
			/// </summary>
			std::vector<u_char> ReadBuffer(uint64_t length);
		};

	}
}