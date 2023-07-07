#include "ProtobufDecoder.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {


		/// <summary>
		/// Constructor.
		/// </summary>
		ProtobufDecoder::ProtobufDecoder(zeek::file_analysis::File* file)
			: file(file){

		}

		/// <summary>
		/// Decodes a buffer that contains a protobuf message.
		/// </summary>
		std::tuple<std::vector<ProtobufPart>, std::vector<u_char>>
		ProtobufDecoder::DecodeProto(std::vector<u_char> data)
		{

			std::vector<ProtobufPart> parts;

			BufferReader reader = BufferReader(data);

			reader.TrySkipGrpcHeader();

			try
			{
				while (reader.LeftBytes() > 0)
				{
					reader.Checkpoint();

					uint64_t byteRangeStart = reader.GetOffset();
					uint64_t byteRangeEnd = 0;
					const auto [indexType, _] = reader.ReadVarint();
					uint64_t type = indexType & 0x7;
					uint64_t index = indexType >> 3;
					std::vector<u_char> value;


					if (type == TYPES::VARINT)
					{
						const auto [number, data] = reader.ReadVarint();
						value = data;
					}
					else if (type == TYPES::LENDELIM)
					{
						const auto [length, _] = reader.ReadVarint();
						value = reader.ReadBuffer(length);
					}
					else if (type == TYPES::FIXED32)
					{
						value = reader.ReadBuffer(4);
					}
					else if (type == TYPES::FIXED64)
					{
						value = reader.ReadBuffer(8);
					}
					else
					{
						throw std::runtime_error("Unknown type");
					}

					byteRangeEnd = reader.GetOffset();

					ProtobufPart part = {byteRangeStart, byteRangeEnd, index, type, value};
					parts.push_back(part);

				}
			}
			catch (const std::exception &e)
			{
				reader.ResetToCheckpoint();
			}

			std::vector<u_char> leftOver = reader.ReadBuffer(reader.LeftBytes());
			return std::make_tuple(parts, leftOver);
		}

		/// <summary>
		/// Decodes a part of a protobuf message.
		/// </summary>
		void ProtobufDecoder::DecodeProtobufPart(ProtobufPart part)
		{
			switch (part.type)
			{
			case TYPES::VARINT:
				break;
			case TYPES::LENDELIM:
			{
				const auto [parts, leftOver] = DecodeProto(part.value);
				if (part.value.size() > 0 && leftOver.size() == 0)
				{
					// part.value is likely to be a sub message
					DecodeProto(parts);
				}
				else
				{
					// part.value is likely to be a string or bytes
					// trigger event using value
					const u_char *data = part.value.data();
					zeek::event_mgr.Enqueue(protobuf_string, file->ToVal(),
											zeek::make_intrusive<zeek::StringVal>(
												new zeek::String(data, part.value.size(), false)));
				}
				break;
			}
			case TYPES::FIXED32:
				// trigger event using value
				break;
			case TYPES::FIXED64:
				// trigger event using value
				break;
			default:
				throw std::runtime_error("Unknown type");
			}
		}

		/// <summary>
		/// Decodes several parts of a protobuf message.
		/// </summary>
		bool ProtobufDecoder::DecodeProto(std::vector<ProtobufPart> parts)
		{
			for (ProtobufPart part : parts)
			{
				DecodeProtobufPart(part);
			}
			return true;
		}

	}
}