#pragma once

#include <iostream>
#include <zeek/plugin/Plugin.h>
#include <zeek/file_analysis/Component.h>
#include <zeek/file_analysis/analyzer/extract/Extract.h>
#include "ProtobufAnalyzer.h"

namespace zeek::plugin {
namespace Demo_ProtobufAnalyzer {

		class Plugin : public zeek::plugin::Plugin
		{
		protected:
			// Overridden from zeek::plugin::Plugin.
			zeek::plugin::Configuration Configure() override;
		};

		extern Plugin plugin;

	}
}
