#include "ProtobufAnalyzer.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		/// <summary>
		/// Instantiates a new ProtobufAnalyzer.
		/// </summary>
		ProtobufAnalyzer::ProtobufAnalyzer(zeek::RecordValPtr args, zeek::file_analysis::File *file)
			: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("PROTOBUF"), std::move(args), file)
		{
		}

		/// <summary>
		/// Overrides the DeliverStream method of the Analyzer class.
		/// </summary>
		bool ProtobufAnalyzer::DeliverStream(const u_char *data, uint64_t len)
		{

			// Keeps the data in memory
			for (uint64_t i = 0; i < len; i++)
			{
				u_char u = data[i];
				buffer.push_back(u);
			}

			return true;
		}

		/// <summary>
		/// Overrides the EndOfFile method of the Analyzer class.
		/// </summary>
		bool ProtobufAnalyzer::EndOfFile()
		{

            ProtobufDecoder *decoder = new ProtobufDecoder(GetFile());
			const auto [parts, _] = decoder->DecodeProto(buffer);
			const auto decodedParts =  decoder->DecodeProto(parts);

            return decodedParts;
		}


		/// <summary>
		/// Instantiates a new ProtobufAnalyzer.
		/// </summary>
		zeek::file_analysis::Analyzer *ProtobufAnalyzer::Instantiate(zeek::RecordValPtr args,
															 zeek::file_analysis::File *file)
		{
			return new ProtobufAnalyzer(std::move(args), file);
		}

}
}