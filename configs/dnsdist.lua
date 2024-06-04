if os.getenv("DEBUG") == 'true' then
    addAction(AllRule(), LogAction("/dev/stdout"))
    addResponseAction(AllRule(), LogResponseAction("/dev/stdout"))
end

function split(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end

    local t = {}

    for str in string.gmatch(inputstr, "([^"..sep.."]+)") do
        table.insert(t, str)
    end

    return t
end

local recursor_dns_servers = os.getenv("RECURSOR_DNS_SERVERS")
local expurgate_dns_servers = os.getenv("EXPURGATE_DNS_SERVERS")

if expurgate_dns_servers then
    local servers = split(expurgate_dns_servers, ",")
    
    for _, server in ipairs(servers) do
        newServer({address=server, pool="expurgate"})
    end

    local expurgate_zone = os.getenv("EXPURGATE_ZONE")

    if expurgate_zone then
        addAction(makeRule(expurgate_zone), PoolAction("expurgate"))
    else
        print("Environment variable EXPURGATE_ZONE not set")
    end
else
    print("Environment variable EXPURGATE_DNS_SERVERS not set")
end

if recursor_dns_servers then
    local servers = split(recursor_dns_servers, ",")
    
    for _, server in ipairs(servers) do
        newServer({address=server, pool="recursor"})
    end

    addAction(AllRule(), PoolAction("recursor"))
else
    print("Environment variable RECURSOR_DNS_SERVERS not set")
end

-- Allow queries from any source
addACL("0.0.0.0/0")
addACL("::/0")

-- Bind dnsdist to all interfaces on port 53
setLocal("0.0.0.0:53")

-- WebServer configuration
local web_password = os.getenv("WEB_PASSWORD")

if web_password then
    webserver("0.0.0.0:8083")
    setWebserverConfig({
        password=hashPassword(web_password),
        acl="0.0.0.0/0"
    })
end
