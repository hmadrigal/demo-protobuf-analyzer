
# Enables http2 analyzer
@load http2

# Enables custom pages (for instance: PROTOBUF)
@load packages

# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -C -r $TRACES/gRPC-SQLi.pcap $PACKAGE %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: sed -i '/^#open/d' 'demo_protobufanalyzer::protobuf.log'
# @TEST-EXEC: sed -i '/^#close/d' 'demo_protobufanalyzer::protobuf.log'
# @TEST-EXEC: mv 'demo_protobufanalyzer::protobuf.log' 'demo_protobufanalyzer_protobuf'
# @TEST-EXEC: btest-diff 'demo_protobufanalyzer_protobuf'