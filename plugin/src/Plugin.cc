#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Demo_ProtobufAnalyzer { Plugin plugin; }

using namespace zeek::plugin::Demo_ProtobufAnalyzer;

/// <summary>
/// Instantiates a new ProtobufAnalyzer.
/// </summary>
zeek::plugin::Configuration Plugin::Configure()
{
	plugin::Demo_ProtobufAnalyzer::plugin.AddComponent(new zeek::file_analysis::Component(
		"PROTOBUF", plugin::Demo_ProtobufAnalyzer::ProtobufAnalyzer::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "Demo::ProtobufAnalyzer";
	config.description = "Prototype for a ProtocolBuf decoder.";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
}
