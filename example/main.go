package main

import (
    "fmt"
    "net"

    "github.com/c93614/wirefilter-go"
)

const (
    ACTION_BLOCK     = iota
    ACTION_CHALLENGE
    ACTION_WHITELIST
)

func load_rules() {
}

func main() {
    // https://developers.cloudflare.com/firewall/cf-firewall-language/operators
    fmt.Print("wirefilter version: ", wirefilter.Version(), "\n")

    schema := wirefilter.NewSchema()
    defer schema.Close()

    schema.AddFields(map[string]wirefilter.Type{
        "http.request.method": wirefilter.TYPE_BYTES,
        "http.user_agent":     wirefilter.TYPE_BYTES,
        "ip.src.ipv4":         wirefilter.TYPE_IP,
        "ip.src.ipv6":         wirefilter.TYPE_IP,
        "ip.geoip.asnum":      wirefilter.TYPE_INT,
        "internal":            wirefilter.TYPE_BOOL,
    })

    ctx := schema.NewExecutionContext()
    defer ctx.Close()

    ctxMap := map[string]interface{}{
        "http.request.method": "GET",
        "http.user_agent":     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.128 Safari/537.36",
        "ip.src.ipv4":         net.ParseIP("1.1.1.1"),
        "ip.src.ipv6":         net.ParseIP("2400:cb00:2049:1::a29f:506"),
        "ip.geoip.asnum":      1111,
        "internal":            true,
    }

    fmt.Println("\n\nExecutionContext:\n------")
    for key, value := range ctxMap {
        fmt.Print(key, ": ", value, "\n")
        ctx.SetFieldValue(key, value)
    }

    fmt.Println("\n\nRules:\n------")
    rules := []string{
        `http.request.method eq "GET"`,
        `http.request.method eq "POST"`,
        `http.user_agent contains "Macintosh"`,
        `http.user_agent contains "MSIE"`,
        `ip.src.ipv4 in {1.1.1.1}`,
        `ip.src.ipv4 in {1.1.1.0/24}`,
        `not (ip.src.ipv4 in {1.1.1.0/24})`,
        `ip.src.ipv4 eq 1.1.1.1`,
        `ip.src.ipv4 == 1.1.1.1`,
        `ip.geoip.asnum == 1111`,
        `ip.geoip.asnum > 1111`,
        `ip.geoip.asnum > 1110`,
        `ip.geoip.asnum 1110`,
        `ip.geoip.asnum eq 1111`,
        `ip.geoip.asnum eq 1112`,
        `ip.geoip.asnum in {1111}`,
        `ip.geoip.asnum in {1112 1002}`,
        `not (ip.geoip.asnum in {1112 1002})`,
        `ip.src.ipv4 in {1.1.1.0..1.1.1.255}`,
        `ip.src.ipv4 in {1.1.1.10..1.1.1.255}`,
        `ip.src.ipv4 in {1.0.0.0/24 10.0.0.0/24}`,
        `ip.src.ipv4 in {1.0.0.0/24 10.0.0.0/24 1.1.1.0/24}`,
        `ip.src.ipv6 in {2400:cb00::/32}`,
        `http.request.method eq "GET" and ip.src.ipv4 in {1.1.1.0/24}`,
        `http.request.method eq "GET" and ip.src.ipv4 in {10.1.1.0/24}`,
        `http.request.method eq "GET" and ip.src.ipv4 in {10.1.1.0/24} or internal`,
        `http.user_agent matches "(?i)(mac|iphone)"`,
        `http.user_agent matches   "mac"`,
    }

    for _, rule := range rules {
        ast, err := schema.Parse(rule)

        if err != nil {
            fmt.Print(rule, "\n=> ", err, "\n\n")
            continue
        }

        //*
        filter := ast.Compile()
        fmt.Print(rule, "\n=> Match: ", filter.Execute(ctx), "\n\n")
        filter.Close()
        /*/
        fmt.Print(rule, "\n=> JSON: ", ast.JSON(), "\n=> Hash: ", ast.Hash(), "\n\n")
        //*/

        ast.Close()
    }
}
