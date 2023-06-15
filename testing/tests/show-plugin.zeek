# @TEST-EXEC: zeek -NN Demo::ProtobufAnalyzer |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
