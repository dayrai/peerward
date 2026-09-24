"""Real kernel NAT/filter topology, confined to the network-none fixture."""
import ipaddress

NAT64_ENDPOINT = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address("fd64:ff9b::")) + int(ipaddress.IPv4Address("10.203.0.1"))))


class Topology:
    def __init__(self, run, case, proxy_port=None):
        self.run, self.case, self.proxy_port = run, case, proxy_port
        self.routers = []

    def inside(self, namespace, *args, **kwargs):
        return self.run("ip", "netns", "exec", namespace, *args, **kwargs)

    def setup(self, namespace, uplink, index):
        run, case = self.run, self.case
        if case == "nat64":
            run("ip", "-n", namespace, "-4", "address", "flush", "dev", "underlay")
            run("ip", "-n", namespace, "-6", "route", "add", "default", "via", "fd42:203::1")
            self.inside(namespace, "nft", "-f", "-", input='table inet fixture { chain output { type filter hook output priority -200; policy accept; ip6 daddr != ' + NAT64_ENDPOINT + ' meta l4proto udp drop; }; }\n')
        elif case == "ipv6":
            # IPv4 remains available to the Relay only; prohibit IPv4 peer UDP.
            self.inside(namespace, "nft", "-f", "-", input='table inet fixture { chain output { type filter hook output priority -200; policy accept; ip daddr != 10.203.0.1 meta l4proto udp drop; }; }\n')
        elif case in ("udp-blocked", "connect", "mtu-blackhole", "one-way-loss"):
            rules = {"udp-blocked": "meta l4proto udp drop;",
                     "connect": f"oifname != \"lo\" oifname != \"pwmesh\" tcp dport != {self.proxy_port or 1} drop; meta l4proto udp drop;",
                     "mtu-blackhole": 'iifname "underlay" meta l4proto udp udp length > 1252 drop;',
                     "one-way-loss": 'ip saddr 10.203.0.1 accept; iifname "underlay" meta l4proto udp numgen random mod 10 < 3 drop;'}
            if case != "one-way-loss" or index == 0:
                # Remote ingress makes MTU/loss silent at sendto and covers
                # both families. Local OUTPUT drops instead report EPERM.
                hook = "input" if case in ("mtu-blackhole", "one-way-loss") else "output"
                self.inside(namespace, "nft", "-f", "-", input=f'table inet fixture {{ chain {hook} {{ type filter hook {hook} priority -200; policy accept; ' + rules[case] + ' }; }\n')
        elif case not in ("lan", "direct-failure", "network-replacement"):
            run("ip", "-n", namespace, "address", "flush", "dev", "underlay")
            run("ip", "-n", namespace, "-6", "address", "flush", "dev", "underlay")
            private = f"10.204.{index}"
            run("ip", "-n", namespace, "address", "add", private + ".2/24", "dev", "underlay")
            run("ip", "-n", namespace, "route", "add", "default", "via", private + ".1")
            router = "nat-" + str(index)
            run("ip", "netns", "add", router)
            self.routers.append(router)
            run("ip", "link", "set", uplink, "nomaster")
            run("ip", "link", "set", uplink, "netns", router)
            run("ip", "-n", router, "address", "add", private + ".1/24", "dev", uplink)
            run("ip", "-n", router, "link", "set", uplink, "up")
            wan = f"wan{index}"
            run("ip", "link", "add", wan, "type", "veth", "peer", "name", "wan", "netns", router)
            if case in ("double-nat", "cgnat"):
                outer = "outer-" + str(index)
                run("ip", "netns", "add", outer)
                self.routers.append(outer)
                transit = f"100.64.{index}" if case == "cgnat" else f"10.205.{index}"
                run("ip", "link", "set", wan, "netns", outer)
                run("ip", "-n", outer, "address", "add", transit + ".1/24", "dev", wan)
                run("ip", "-n", outer, "link", "set", wan, "up")
                run("ip", "-n", router, "address", "add", transit + ".2/24", "dev", "wan")
                run("ip", "-n", router, "link", "set", "wan", "up")
                run("ip", "-n", router, "route", "add", "default", "via", transit + ".1")
                outer_wan = f"outwan{index}"
                run("ip", "link", "add", outer_wan, "type", "veth", "peer", "name", "wan", "netns", outer)
                run("ip", "link", "set", outer_wan, "master", "brpwd")
                run("ip", "link", "set", outer_wan, "up")
                run("ip", "-n", outer, "address", "add", f"10.203.0.{index+2}/24", "dev", "wan")
                self.nat(outer, wan, "masquerade")
            else:
                run("ip", "link", "set", wan, "master", "brpwd")
                run("ip", "link", "set", wan, "up")
                run("ip", "-n", router, "address", "add", f"10.203.0.{index+2}/24", "dev", "wan")
            translation = "masquerade"
            if case == "endpoint-dependent":
                translation = f'meta l4proto udp ip daddr 10.203.0.1 snat to 10.203.0.{index+2}:40000-40999; oifname "wan" meta l4proto udp snat to 10.203.0.{index+2}:42000-42999; oifname "wan" masquerade'
            elif case == "random-mapping":
                translation = f'meta l4proto udp snat to 10.203.0.{index+2}:40000-60000 fully-random; oifname "wan" masquerade'
            self.nat(router, uplink, translation)

    def nat(self, router, lan, translation):
        run = self.run
        run("ip", "-n", router, "link", "set", "lo", "up")
        run("ip", "-n", router, "link", "set", "wan", "up")
        self.inside(router, "sysctl", "-qw", "net.ipv4.ip_forward=1")
        self.inside(router, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
        self.inside(router, "nft", "-f", "-", input=f'''table ip fixture_nat {{
 chain input {{ type filter hook input priority 0; policy accept; iifname "wan" ct state new drop; }}
 chain forward {{ type filter hook forward priority 0; policy drop; ct state established,related accept; iifname "{lan}" accept; }}
 chain postrouting {{ type nat hook postrouting priority 100; policy accept; oifname "wan" {translation}; }}
}}''')

    def reset(self):
        for router in self.routers:
            self.inside(router, "conntrack", "-F")
