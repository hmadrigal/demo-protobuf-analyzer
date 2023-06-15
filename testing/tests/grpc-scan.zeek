
# Enables http2 analyzer
@load http2

# Enables custom pages (for instance: PROTOBUF)
@load packages

# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/gRPC.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output


event protobuf_string(f: fa_file, text: string)
{
    print text;
}