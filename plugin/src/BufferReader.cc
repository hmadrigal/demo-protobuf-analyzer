#include "BufferReader.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		/// <summary>
		/// Receives a buffer as paramters, and provides methods to read data from it.
		/// </summary>
		BufferReader::BufferReader(std::vector<u_char> data)
		{
			buffer = data;
			offset = 0;
		}

		/// <summary>
		/// Get the current offset of the reader.
		/// </summary>
		uint64_t BufferReader::GetOffset()
		{
			return offset;
		}

		/// <summary>
		/// Reads a varint-encoded integer from the buffer.
		/// </summary>
		std::tuple<uint64_t, std::vector<u_char>> BufferReader::ReadVarint()
		{
			const auto [value, length] = DecodeVarint(buffer, offset);
			std::vector<u_char> data(buffer.begin() + offset, buffer.begin() + offset + length + 1);
			offset += length;

			return std::make_tuple(value, data);
		}


		/// <summary>
		/// Checks if there are enough bytes left in the buffer.
		/// </summary>
		void BufferReader::CheckBytesLeft(uint64_t length)
		{
			if (length > LeftBytes())
			{
				throw std::runtime_error("Not enough bytes left in the buffer");
			}
		}

		/// <summary>
		/// Reads a byte from the buffer.
		/// </summary>
		std::vector<u_char> BufferReader::ReadBuffer(uint64_t length)
		{
			CheckBytesLeft(length);
			std::vector<u_char> res;
			for (uint64_t i = 0; i < length; i++)
			{
				res.push_back(buffer[offset++]);
			}
			return res;
		}

		/// <summary>
		/// Reads the remaining bytes from the buffer.
		/// </summary>
		uint64_t BufferReader::LeftBytes()
		{
			return buffer.size() - offset;
		}

		/// <summary>
		/// Sets a checkpoint to the current offset.
		/// </summary>
		void BufferReader::Checkpoint(void)
		{
			savedOffset = offset;
		}

		/// <summary>
		/// Resets the offset to the last checkpoint.
		/// </summary>
		void BufferReader::ResetToCheckpoint(void)
		{
			offset = savedOffset;
		}

		/// <summary>
		/// Tries to skip the gRPC header. Some gRPC messages have a header that we need to skip.
		/// </summary>
		void BufferReader::TrySkipGrpcHeader()
		{
			uint64_t backupOffset = offset;

			if (buffer[offset] == 0 && LeftBytes() >= 5)
			{
				offset++;
				uint64_t length = ReadInt32BE(buffer, offset);
				offset += 4;

				if (length > LeftBytes())
				{
					offset = backupOffset;
				}
			}
		}

		/// <summary>
		/// Decodes a Int32 from a buffer.
		/// </summary>
		int32_t BufferReader::ReadInt32BE(std::vector<u_char> data, uint64_t offset)
		{
			return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
		}

	}
}