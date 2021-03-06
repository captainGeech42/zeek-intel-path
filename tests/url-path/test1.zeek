#
# @TEST-EXEC: zeek -C -r $TRACES/http.pcapng ../../../scripts/url-path %INPUT
# @TEST-EXEC: btest-diff intel.log

# This test will alert on /malware using original_URI

@load policy/frameworks/intel/seen

event zeek_init()
    {
    suspend_processing();

    Intel::insert([
        $indicator = "/malware",
        $indicator_type = Intel::URL_PATH,
        $meta = [$source = "Test IOC"]]);

    continue_processing();
    }
