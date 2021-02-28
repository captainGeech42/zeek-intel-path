#
# @TEST-EXEC: zeek -C -r $TRACES/http_trace.pcapng ../../../scripts/url-path %INPUT
# @TEST-EXEC: btest-diff intel.log

# This test will flag on /malware.exe

@load policy/frameworks/intel/seen

redef Intel::read_files += { "../intel/test1.intel" };