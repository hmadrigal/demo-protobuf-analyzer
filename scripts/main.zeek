# Enables http2 analyzer
@load http2

module Demo::ProtobufAnalyzer;

# Enable or disable debug messages
global ProtobufAnalyzerDebug: bool = F;

# =============================== Handling gRPC text event

export {
	type ProtoInfo: record 
    {
		is_protobuf: bool &optional;
        stream: count &optional;
        is_orig: bool &optional;
        method: string &optional;
        authority: string &optional;
        host: string &optional;
        original_URI: string &optional;
	};
}

redef record HTTP2::Info += {
    proto:          ProtoInfo  &optional;
};

redef record fa_file += {
    proto:          ProtoInfo  &optional;
};

const protobuf_mime_types =  
    
    # https://developers.cloudflare.com/support/speed/optimization-file-size/what-will-cloudflare-compress/
    /^"application\/x-protobuf"/ |
    # https://groups.google.com/g/protobuf/c/VAoJ-HtgpAI
    /^"application\/vnd.google\.protobuf"/ |
    # https://datatracker.ietf.org/doc/html/draft-rfernando-protocol-buffers-00
    /^"application\/protobuf"/ | 
    # https://stackoverflow.com/questions/30505408/what-is-the-correct-protobuf-content-type
    /^"application\/octet-stream"/ |
    # https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
    /^"application\/grpc"/ |
    # NOTE: This is not a valid mime type, but it is used in replies from the server
    /^"text\/plain"/
 ;

event zeek_init()
{
	print "ProtobufAnalyzer loaded";
}

event http2_request(c: connection, is_orig: bool, stream: count, method: string, authority: string, host: string, original_URI: string, unescaped_URI: string, version: string, push: bool)
{

@if ( ProtobufAnalyzerDebug )
    print "[http2_request]";
    print "    method", method;
    print "    authority", authority;
    print "    host", host;
    print "    original_URI", original_URI;
    print "    unescaped_URI", unescaped_URI;
    print "    version", version;
    print "    push", push;
@endif

    c$http2$proto = ProtoInfo();
    c$http2$proto$is_protobuf = F;
    c$http2$proto$stream = stream;
    c$http2$proto$is_orig = is_orig;
    c$http2$proto$method = method;
    c$http2$proto$authority = authority;
    c$http2$proto$host = host;
    c$http2$proto$original_URI = original_URI;
}

event http2_stream_end(c: connection, stream: count, stats: http2_stream_stat)
{
    if ( c?$http2 && c$http2?$proto)
    {
        delete c$http2$proto;
    }
}

event http2_content_type(c: connection, is_orig: bool, stream: count, contentType: string)
{

@if ( ProtobufAnalyzerDebug )
    print "[http2_content_type]";
    print "    contentType", contentType;
    print "    is_orig", is_orig;
    print "    stream", stream;
@endif

    
    if ( protobuf_mime_types in contentType ) 
    {
        
@if ( ProtobufAnalyzerDebug )
        print "    contentType is protobuf: ", contentType;
@endif

        c$http2$proto$is_protobuf = T;

    }

    # print "";

}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
{
@if ( ProtobufAnalyzerDebug )
    print "[file_over_new_connection]";
@endif
    if ( c?$http2 )
    {
        if ( c$http2?$proto )
        {
            f$proto = c$http2$proto;
        }
		else
		{
@if ( ProtobufAnalyzerDebug )
            print "    no proto info on http2 connection";
@endif

        }
    }
	else
	{
@if ( ProtobufAnalyzerDebug )
        print "    no http2 info on connection";
@endif
    }

    # print "";

}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
{
    # print "[file_sniff]";
    Files::add_analyzer(f, Files::ANALYZER_PROTOBUF);


    if (f?$proto
        && f$proto$is_protobuf == T)
    {
@if ( ProtobufAnalyzerDebug )
        print "PROTO FILE DETECTED!! Calling ANALYZER_PROTOBUF";
@endif

        Files::add_analyzer(f, Files::ANALYZER_PROTOBUF);
    }
    else
    {
@if ( ProtobufAnalyzerDebug )
        print "    proto info is not protobuf or is_protobuf is false";
@endif

    }


    # print "";
}

# =============================== Handling gRPC text event
event protobuf_string(f: fa_file, text: string)
{

@if ( ProtobufAnalyzerDebug )
    print "[protobuf_string]";
    print "    text", text;
    # print "    f.proto", f$proto;
    print "    method", f$proto$method;
    print "    host", f$proto$host;
    print "    authority", f$proto$authority;
    print "    original_URI", f$proto$original_URI;
    # print "    unescaped_URI", f$proto$unescaped_URI;
    # print "    version", f$proto$version;
@endif


    local is_sqli = Demo::ProtobufAnalyzer::is_sql_injection(text, |text|);

@if ( ProtobufAnalyzerDebug )
    print "    is_sql_injection", is_sqli;
@endif

    if ( is_sqli )
    {

        print "===> SQL INJECTION DETECTED!! *** ";
        print "    text", text;
        # print "    f.proto", f$proto;
        print "    method", f$proto$method;
        print "    host", f$proto$host;
        print "    authority", f$proto$authority;
        print "    original_URI", f$proto$original_URI;
        # print "    unescaped_URI", f$proto$unescaped_URI;
        # print "    version", f$proto$version;
    
        # Demo::ProtobufAnalyzer::report_sql_injection(f, text, method, host, authority, original_URI, unescaped_URI, version);
    }

    # print "";


}