#
# @TEST-EXEC: zeek -C -r $TRACES/http.pcapng ../../../scripts/url-path %INPUT
# @TEST-EXEC: btest-diff intel.log

# This test will alert on /mal-ware using unescaped_URI

@load policy/frameworks/intel/seen

redef Intel::seen_unescaped_uri = T;

event zeek_init()
    {
    suspend_processing();

    Intel::insert([
        $indicator = "/mal-ware",
        $indicator_type = Intel::URL_PATH,
        $meta = [$source = "Test IOC"]]);

    continue_processing();
    }
