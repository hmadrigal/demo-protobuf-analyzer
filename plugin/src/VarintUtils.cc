
#include "VarintUtils.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		std::tuple<uint64_t, uint64_t> DecodeVarint(std::vector<u_char> buffer, uint64_t offset)
		{
			uint64_t res = 0;
			uint64_t shift = 0;
			uint64_t currentByte;
			uint64_t counter = 0;

			do {

				if (offset >= buffer.size())
				{
					throw std::runtime_error("Buffer out of bounds");
				}

				if (counter > 10)
				{
					throw std::runtime_error("Varint too long");
				}

				currentByte = buffer[offset++];
				counter++;

				// defines multiplier as 2 power of shift
				uint64_t multiplier = 1 << shift;
				// defines thisByteValue as currentByte with 7 bits factor by multiplier
				uint64_t thisByteValue = (currentByte & 0x7f) * multiplier;

				shift += 7;
				res += thisByteValue;


			}while (currentByte >= 0x80);


			return std::make_tuple(res, shift / 7);
		}

		// std::tuple<uint64_t, uint64_t> DecodeVarint(std::vector<u_char> buffer, uint64_t offset)
		// {
		// 	uint64_t value = 0;
		// 	uint64_t shift = 0;
		// 	uint64_t currentByte;
		// 	uint64_t counter = 0;
		// 	do
		// 	{
		// 		if (offset >= buffer.size())
		// 		{
		// 			throw std::runtime_error("Buffer out of bounds");
		// 		}
		// 		currentByte = buffer[offset++];
		// 		// std::cout << "Current byte: " << currentByte << " at " << offset-1 << std::endl;
		// 		value |= (currentByte & 0x7f) << shift;
		// 		shift += 7;

		// 		counter++;
		// 		if (counter > 10)
		// 		{
		// 			// std::cout << "Varint too long" << std::endl;
		// 			throw std::runtime_error("Varint too long");
		// 		}

		// 	} while (currentByte & 0x80);
		// 	//} while (currentByte >= 0x80);

		// 	return std::make_tuple(value, offset / 7);
		// }

	}
}