#pragma once

#include <iostream>
#include <zeek/plugin/Plugin.h>
#include <zeek/file_analysis/Component.h>
#include <zeek/file_analysis/analyzer/extract/Extract.h>
#include "ProtobufAnalyzer.h"

namespace Pipoca {
namespace Protobuf {

		/// <summary>
		/// A class that represents the plugin.
		/// </summary>
		class Plugin : public zeek::plugin::Plugin
		{
		protected:
			/// <summary>
			/// Instantiates a new ProtobufAnalyzer.
			/// </summary>
			zeek::plugin::Configuration Configure() override;
		};

		extern Plugin plugin;

	}
}
