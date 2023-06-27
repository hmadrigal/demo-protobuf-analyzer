# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/bench_MySQL.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

# @TEST-EXEC: sed -i '/^#open/d' sqli_grpc.log
# @TEST-EXEC: sed -i '/^#close/d' sqli_grpc.log
# @TEST-EXEC: btest-diff sqli_grpc.log

@load protobuf
@load protobuf/sqli-detect

event protobuf_string(f: fa_file, text: string)
{
    local is_sqli = Pipoca::ProtobufAnalyzer::is_sqli_by_libinjection(text, |text|);
    print fmt("is_sqli: %s string: %s", is_sqli, text);
}