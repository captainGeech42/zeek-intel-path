##! This script adds support for URL path indicators in the Intel framework

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

module Intel;

export {
    redef enum Intel::Type += {
        URL_PATH
    };
}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    Intel::seen([
        $indicator = original_URI,
        $indicator_type = Intel::URL_PATH,
        $where = HTTP::IN_URL,
        $conn = c]);
    }