# Enables http2 analyzer
@load http2

# Enables file analysis
@load base/frameworks/notice

module Demo::ProtobufAnalyzer;

# Enable or disable debug messages
global ProtobufAnalyzerDebug: bool = F;


export {
    # record to exchange information between http2 and file analysis
	type ProtoInfo: record 
    {
		is_protobuf: bool &optional;
        stream: count &optional;
        is_orig: bool &optional;
        method: string &optional;
        authority: string &optional;
        host: string &optional;
        original_URI: string &optional;
        orig_h: addr &optional;
        orig_p: port &optional;
        resp_h: addr &optional;
        resp_p: port &optional;
	};

    # Extends HTTP2::Info record to add a ProtoInfo
    redef record HTTP2::Info += {
        proto:          ProtoInfo  &optional;
    };

    # Extends file_analysis::fa_file record to add a ProtoInfo
    redef record fa_file += {
        proto:          ProtoInfo  &optional;
    };

    # Extends Notice::Type enum to add a SQL_Injection
    redef enum Notice::Type += {
        SQL_Injection,
    };

    # Extends Log::ID enumer to add a PROTOBUF_LOG
    redef enum Log::ID += {
        PROTOBUF_LOG
    };

    # Data structure to store protobuf log events
    type ProtobufLog: record {
        # stream: count &log;
        # Sis_orig: bool &log;
        method: string &log;
        authority: string &log;
        host: string &log;
        original_URI: string &log;
        text: string &log;
        # orig_h: addr &log;
        # orig_p: port &log;
        # resp_h: addr &log;
        # resp_p: port &log;
    };

    global log_protobuf: event(rec: ProtobufLog);
}

# Regular expression (pattern) to detect protobuf mime types
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

 	## Regular expression is used to match URI based SQL injections.
    ## Taken from scripts/policy/protocols/http/detect-sqli.zeek at Zeeks repository
	const match_sql_injection_uri =
		  /[\?&][^[:blank:]\x00-\x1f\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x1f]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x1f]|\/\*.*?\*\/)+/
		| /[\?&][^[:blank:]\x00-\x1f\|]+?=[\-0-9%]+([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x1f]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x1f]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS])/
		| /[\?&][^[:blank:]\x00-\x1f]+?=[\-0-9%]*([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT])/
		| /[\?&][^[:blank:]\x00-\x1f\|]+?=([[:blank:]\x00-\x1f]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x1f]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x1f]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}/
		| /[\?&][^[:blank:]\x00-\x1f]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(/
		| /\/\*![[:digit:]]{5}.*?\*\// ;

event zeek_init()
{
@if ( ProtobufAnalyzerDebug )        
	print "ProtobufAnalyzer loaded";
@endif

    Log::create_stream(PROTOBUF_LOG, [$columns=ProtobufLog, $ev=log_protobuf]);
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
    c$http2$proto$orig_h = c$id$orig_h;
    c$http2$proto$orig_p = c$id$orig_p;
    c$http2$proto$resp_h = c$id$resp_h;
    c$http2$proto$resp_p = c$id$resp_p;
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


}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
{
@if ( ProtobufAnalyzerDebug )
    print "[file_sniff]";
@endif


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


}

event protobuf_string(f: fa_file, text: string)
{

@if ( ProtobufAnalyzerDebug )
    print "[protobuf_string]";
    print "    text", text;
    print "    method", f$proto$method;
    print "    host", f$proto$host;
    print "    authority", f$proto$authority;
    print "    original_URI", f$proto$original_URI;
    print "    orig_h", f$proto$orig_h;
    print "    orig_p", f$proto$orig_p;
    print "    resp_h", f$proto$resp_h;
    print "    resp_p", f$proto$resp_p;
@endif


    local is_sqli = is_sql_injection(text, |text|) || ( match_sql_injection_uri in text );

@if ( ProtobufAnalyzerDebug )
    print "    is_sql_injection", is_sqli;
@endif

    if ( is_sqli )
    {

@if ( ProtobufAnalyzerDebug )
        print "===> SQL INJECTION DETECTED!! *** ";
@endif
        # Notice the user about the SQL injection
		NOTICE( [ 
            $note=SQL_Injection, 
            $msg=fmt(
                "A SQL injection has been detected."
                + "    method: %s"
                + "    host: %s"
                + "    authority: %s"
                + "    original_URI: %s" 
                + "    text: %s" 
                # + "    orig_h" + f$proto$orig_h
                # + "    orig_p" + f$proto$orig_p
                # + "    resp_h" + f$proto$resp_h
                # + "    resp_p" + f$proto$resp_p
                , text, f$proto$method, f$proto$host, f$proto$authority, f$proto$original_URI ) ]
        );

        # Adding log entry
        local log_entry : ProtobufLog;
        log_entry$method = f$proto$method;
        log_entry$host = f$proto$host;
        log_entry$authority = f$proto$authority;
        log_entry$original_URI = f$proto$original_URI;
        # log_entry$orig_h = f$proto$orig_h;
        # log_entry$orig_p = f$proto$orig_p;
        # log_entry$resp_h = f$proto$resp_h;
        # log_entry$resp_p = f$proto$resp_p;
        log_entry$text = text;
        # log_entry$timestamp = network_time();
        Log::write(PROTOBUF_LOG, log_entry);
    }



}