#include "ProtobufAnalyzer.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		ProtobufAnalyzer::ProtobufAnalyzer(zeek::RecordValPtr args, zeek::file_analysis::File *file)
			: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("PROTOBUF"), std::move(args), file)
		{
		}

		bool ProtobufAnalyzer::DeliverStream(const u_char *data, uint64_t len)
		{
			// std::cout << "Running: Protobuf::DeliverStream segment: " << len << std::endl;

			// Keeps the data in memory
			for (uint64_t i = 0; i < len; i++)
			{
				u_char u = data[i];
				buffer.push_back(u);
				// std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)u << " ";
			}

			return true;
		}

		bool ProtobufAnalyzer::EndOfFile()
		{

            ProtobufDecoder *decoder = new ProtobufDecoder(GetFile());


			// std::cout << "Running: Protobuf::EndOfFile size: " << buffer.size() << std::endl;

			// for (uint64_t i = 0; i < buffer.size(); i++)
			// {
			// 	std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)buffer[i] << " ";
			// }
			const auto [parts, _] = decoder->DecodeProto(buffer);

			// for (auto part : parts)
			// {
			// 	std::cout  << "byteRange: [" << part.byteRangeStart << "," << part.byteRangeEnd << "] index: " << part.index << " type: " << part.type << " value: ";
			// 	for (auto v : part.value)
			// 	{
			// 		// std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)v << " ";
			// 		std::cout << (int)v << " ";
			// 	}
			// }

			const auto decodedParts =  decoder->DecodeProto(parts);

            return decodedParts;
		}


		zeek::file_analysis::Analyzer *ProtobufAnalyzer::Instantiate(zeek::RecordValPtr args,
															 zeek::file_analysis::File *file)
		{
			return new ProtobufAnalyzer(std::move(args), file);
		}

}
}