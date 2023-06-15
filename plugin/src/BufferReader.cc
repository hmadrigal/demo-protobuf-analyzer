#include "BufferReader.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		BufferReader::BufferReader(std::vector<u_char> data)
		{
			buffer = data;
			offset = 0;

			// for (uint64_t i = 0; i < buffer.size(); i++)
			// {
			// 	std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
			// }
		}

		uint64_t BufferReader::GetOffset()
		{
			return offset;
		}

		std::tuple<uint64_t, std::vector<u_char>> BufferReader::ReadVarint()
		{
			const auto [value, length] = DecodeVarint(buffer, offset);
			std::vector<u_char> data(buffer.begin() + offset, buffer.begin() + offset + length + 1);
			offset += length;

			// std::cout << "[VAR] value: " << value << " length: " << length << std::endl;

			return std::make_tuple(value, data);
		}

		std::vector<u_char> BufferReader::ReadBuffer(uint64_t length)
		{
			std::vector<u_char> res;
			for (uint64_t i = 0; i < length; i++)
			{
				res.push_back(buffer[offset++]);
			}
			return res;
		}

		uint64_t BufferReader::LeftBytes()
		{
			return buffer.size() - offset;
		}

		void BufferReader::Checkpoint(void)
		{
			savedOffset = offset;
		}

		void BufferReader::ResetToCheckpoint(void)
		{
			offset = savedOffset;
		}

		void BufferReader::TrySkipGrpcHeader()
		{
			uint64_t backupOffset = offset;

			if (buffer[offset] == 0 && LeftBytes() >= 5)
			{
				offset++;
				uint64_t length = ReadInt32BE(buffer, offset);
				// std::cout << "Grpc header length: " << length << std::endl;
				offset += 4;

				if (length > LeftBytes())
				{
					// Something is wrong, revert
					offset = backupOffset;
				}
			}
		}

		int32_t BufferReader::ReadInt32BE(std::vector<u_char> data, uint64_t offset)
		{
			return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
		}

	}
}