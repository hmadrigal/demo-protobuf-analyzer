#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Demo_ProtobufAnalyzer { Plugin plugin; }

using namespace zeek::plugin::Demo_ProtobufAnalyzer;

zeek::plugin::Configuration Plugin::Configure()
{
	plugin::Demo_ProtobufAnalyzer::plugin.AddComponent(new zeek::file_analysis::Component(
		"PROTOBUF", plugin::Demo_ProtobufAnalyzer::ProtobufAnalyzer::Instantiate));

	// std::cout << "Running: plugin::Demo_ProtobufAnalyzer" << std::endl;
	
	zeek::plugin::Configuration config;
	config.name = "Demo::ProtobufAnalyzer";
	config.description = "Prototype for a ProtocolBuf decoder.";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
}
