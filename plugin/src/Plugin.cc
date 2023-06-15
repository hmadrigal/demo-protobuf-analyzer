#include "config.h"
#include "Plugin.h"

namespace zeek::plugin::Demo_ProtobufAnalyzer { Plugin plugin; }

using namespace zeek::plugin::Demo_ProtobufAnalyzer;

zeek::plugin::Configuration Plugin::Configure()
	{
	zeek::plugin::Configuration config;
	config.name = "Demo::ProtobufAnalyzer";
	config.description = "TODO: Insert description";
	config.version.major = VERSION_MAJOR;
	config.version.minor = VERSION_MINOR;
	config.version.patch = VERSION_PATCH;
	return config;
	}
