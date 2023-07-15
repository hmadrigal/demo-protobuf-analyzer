# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/sql_injection.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

@load protobuf

event protobuf_string(f: fa_file, text: string)
{
    local is_sqli = Pipoca::ProtobufAnalyzer::is_sqli_by_libinjection(text, |text|);
    print fmt("is_sqli: %s string: %s", is_sqli, text);
}