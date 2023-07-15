#include "config.h"
#include "Plugin.h"

namespace Pipoca::Protobuf { Plugin plugin; }

using namespace Pipoca::Protobuf;

/// <summary>
/// Instantiates a new ProtobufAnalyzer.
/// </summary>
zeek::plugin::Configuration Plugin::Configure()
{
	Pipoca::Protobuf::plugin.AddComponent(new zeek::file_analysis::Component(
		"PROTOBUF", Pipoca::Protobuf::ProtobufAnalyzer::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Pipoca::ProtobufAnalyzer";
	config.description = "Prototype for a ProtocolBuf decoder.";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
}
