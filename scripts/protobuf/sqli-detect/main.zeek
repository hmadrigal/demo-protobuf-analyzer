module Pipoca::Protobuf::SQLi;

export {
    # Extends Log::ID enumer to add a LOG
    redef enum Log::ID += { LOG };

    global log_policy: Log::PolicyHook;

    # Data structure to store protobuf log events
    type Info: record {
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

    global log_sqli_grpc: event(rec: Info);

}


event zeek_init() &priority=5
{
	Log::create_stream(LOG, [$columns=Info, $ev=log_sqli_grpc, $path="sqli_grpc", $policy=log_policy]);
}

event protobuf_string(f: fa_file, text: string)
{

    local is_sqli = Pipoca::ProtobufAnalyzer::is_sqli_by_libinjection(text, |text|);

    if ( is_sqli )
    {

        # Adding log entry
        local log_entry : Info;
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

        Log::write(LOG, log_entry);
        
    }



}