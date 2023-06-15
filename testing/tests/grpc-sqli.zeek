
# Enables http2 analyzer
@load http2

# Enables custom pages (for instance: PROTOBUF)
@load packages

# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/gRPC-SQLi.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output
