# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/analyze_string.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output

@load protobuf

event protobuf_string(f: fa_file, text: string)
{
    print fmt("string: %s", text);
}