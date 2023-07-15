# @TEST-EXEC: zeek -NN Pipoca::ProtobufAnalyzer |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
