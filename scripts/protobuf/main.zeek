# Enables http2 analyzer
@load http2

module Pipoca::Protobuf;

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
    /^"application\/grpc"/ 
 ;

event http2_request(c: connection, is_orig: bool, stream: count, method: string, authority: string, host: string, original_URI: string, unescaped_URI: string, version: string, push: bool)
{
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
    if ( protobuf_mime_types in contentType ) 
    {
        c$http2$proto$is_protobuf = T;
    }
}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool) &priority=5
{
    if ( c?$http2 
        && c$http2?$proto)
    {
            f$proto = c$http2$proto;
    }
}

event file_sniff(f: fa_file, meta: fa_metadata) &priority=5
{
    if (f?$proto
        && f$proto$is_protobuf == T)
    {
        Files::add_analyzer(f, Files::ANALYZER_PROTOBUF);
    }
}