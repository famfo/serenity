/*
 * Copyright (c) 2018-2021, Andreas Kling <kling@serenityos.org>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "AK/IpAddressCidr.h"
#include <AK/HashMap.h>
#include <AK/Singleton.h>
#include <Kernel/Debug.h>
#include <Kernel/Locking/MutexProtected.h>
#include <Kernel/Net/LoopbackAdapter.h>
#include <Kernel/Net/NetworkTask.h>
#include <Kernel/Net/NetworkingManagement.h>
#include <Kernel/Net/Routing.h>
#include <Kernel/Tasks/Thread.h>

namespace Kernel {

static Singleton<SpinlockProtected<HashMap<IPv4Address, MACAddress>, LockRank::None>> s_arp_table;
static Singleton<SpinlockProtected<Route::RouteList, LockRank::None>> s_routing_table;

class ARPTableBlocker final : public Thread::Blocker {
public:
    ARPTableBlocker(IPv4Address ip_addr, Optional<MACAddress>& addr);

    virtual StringView state_string() const override { return "Routing (ARP)"sv; }
    virtual Type blocker_type() const override { return Type::Routing; }
    virtual bool setup_blocker() override;

    virtual void will_unblock_immediately_without_blocking(UnblockImmediatelyReason) override;

    bool unblock_if_matching_ip_address(bool from_add_blocker, IPv4Address const& ip_address, MACAddress const& mac_address)
    {
        if (m_ip_address != ip_address)
            return false;

        {
            SpinlockLocker lock(m_lock);
            if (m_did_unblock)
                return false;
            m_did_unblock = true;
            m_mac_address = mac_address;
        }

        if (!from_add_blocker)
            unblock_from_blocker();
        return true;
    }

    IPv4Address const& ip_address() const { return m_ip_address; }

private:
    IPv4Address const m_ip_address;
    Optional<MACAddress>& m_mac_address;
    bool m_did_unblock { false };
};

class ARPTableBlockerSet final : public Thread::BlockerSet {
public:
    void unblock_blockers_waiting_for_ipv4_address(IPv4Address const& ipv4_address, MACAddress const& mac_address)
    {
        BlockerSet::unblock_all_blockers_whose_conditions_are_met([&](auto& b, void*, bool&) {
            VERIFY(b.blocker_type() == Thread::Blocker::Type::Routing);
            auto& blocker = static_cast<ARPTableBlocker&>(b);
            return blocker.unblock_if_matching_ip_address(false, ipv4_address, mac_address);
        });
    }

protected:
    virtual bool should_add_blocker(Thread::Blocker& b, void*) override
    {
        VERIFY(b.blocker_type() == Thread::Blocker::Type::Routing);
        auto& blocker = static_cast<ARPTableBlocker&>(b);
        auto maybe_mac_address = arp_table().with([&](auto const& table) -> auto {
            return table.get(blocker.ip_address());
        });
        if (!maybe_mac_address.has_value())
            return true;
        return !blocker.unblock_if_matching_ip_address(true, blocker.ip_address(), maybe_mac_address.value());
    }
};

static Singleton<ARPTableBlockerSet> s_arp_table_blocker_set;

ARPTableBlocker::ARPTableBlocker(IPv4Address ip_addr, Optional<MACAddress>& addr)
    : m_ip_address(ip_addr)
    , m_mac_address(addr)
{
}

bool ARPTableBlocker::setup_blocker()
{
    return add_to_blocker_set(*s_arp_table_blocker_set);
}

void ARPTableBlocker::will_unblock_immediately_without_blocking(UnblockImmediatelyReason)
{
    auto addr = arp_table().with([&](auto const& table) -> auto {
        return table.get(ip_address());
    });

    SpinlockLocker lock(m_lock);
    if (!m_did_unblock) {
        m_did_unblock = true;
        m_mac_address = move(addr);
    }
}

SpinlockProtected<HashMap<IPv4Address, MACAddress>, LockRank::None>& arp_table()
{
    return *s_arp_table;
}

void update_arp_table(IPv4Address const& ip_addr, MACAddress const& addr, UpdateTable update)
{
    arp_table().with([&](auto& table) {
        if (update == UpdateTable::Set)
            table.set(ip_addr, addr);
        if (update == UpdateTable::Delete)
            table.remove(ip_addr);
    });
    s_arp_table_blocker_set->unblock_blockers_waiting_for_ipv4_address(ip_addr, addr);

    if constexpr (ARP_DEBUG) {
        arp_table().with([&](auto const& table) {
            dmesgln("ARP table ({} entries):", table.size());
            for (auto& it : table)
                dmesgln("{} :: {}", it.value.to_string(), it.key.to_string());
        });
    }
}

SpinlockProtected<Route::RouteList, LockRank::None>& routing_table()
{
    return *s_routing_table;
}

ErrorOr<void> update_routing_table(IPv4AddressCidr const& destination, IPv4Address const& gateway, u16 flags, RefPtr<NetworkAdapter> adapter, UpdateTable update)
{
    dbgln_if(ROUTING_DEBUG, "update_routing_table {} {} {} {} {}", destination, gateway, flags, adapter, update == UpdateTable::Set ? "Set" : "Delete");

    auto route_entry = adopt_ref_if_nonnull(new (nothrow) Route { destination, gateway, flags, adapter.release_nonnull() });
    if (!route_entry)
        return ENOMEM;

    TRY(routing_table().with([&](auto& table) -> ErrorOr<void> {
        if (update == UpdateTable::Set) {
            for (auto const& route : table) {
                if (route == *route_entry)
                    return EEXIST;
            }
            table.append(*route_entry);
        }
        if (update == UpdateTable::Delete) {
            for (auto& route : table) {
                dbgln_if(ROUTING_DEBUG, "candidate: {} {} {} {}", route.destination, route.gateway, route.flags, route.adapter);
                if (route.matches(*route_entry)) {
                    // FIXME: Remove all entries, not only the first one.
                    table.remove(route);
                    return {};
                }
            }
            return ESRCH;
        }
        return {};
    }));

    return {};
}

bool RoutingDecision::is_zero() const
{
    return adapter.is_null() || next_hop.is_zero();
}

static MACAddress multicast_ethernet_address(IPv4Address const& address)
{
    return MACAddress { 0x01, 0x00, 0x5e, (u8)(address[1] & 0x7f), address[2], address[3] };
}

RoutingDecision route_to(IPv4Address const& target, IPv4Address const& source, RefPtr<NetworkAdapter> const through, AllowBroadcast allow_broadcast, AllowUsingGateway allow_using_gateway)
{
    auto matches = [&](auto& adapter) {
        if (!through)
            return true;

        return through == adapter;
    };
    auto if_matches = [&](auto& adapter, auto const& mac, auto source_address) -> RoutingDecision {
        if (!matches(adapter))
            return { nullptr, {}, {} };
        return { adapter, mac, source_address };
    };

    // FIXME: the localhost origin address is not always 127.0.0.1
    if (target.to_u32() == 0 || target[0] == 127)
        return if_matches(*NetworkingManagement::the().loopback_adapter(), NetworkingManagement::the().loopback_adapter()->mac_address(), IPv4Address(127, 0, 0, 1));

    RefPtr<NetworkAdapter> local_adapter = nullptr;
    RefPtr<Route> chosen_route = nullptr;

    NetworkingManagement::the().for_each([source, &target, &local_adapter, &matches, &through](NetworkAdapter& adapter) {
        auto local_addresses = adapter.ipv4_addresses();
        for (auto entry : local_addresses) {
            auto address = IPv4AddressCidr(entry.key, entry.value);
            dbgln("route_to: trying {} {} for target {}", local_adapter->name(), address, target);

            if (source == address.ip_address()) {
                local_adapter = NetworkingManagement::the().loopback_adapter();
                return;
            }

            if (!adapter.link_up() || (address.ip_address().to_u32() == 0 && !through))
                return;

            if (source.to_u32() != 0 && source != address.ip_address())
                continue;

            if (address.contains(target) && matches(adapter)) {
                local_adapter = adapter;
                return;
            }
        }
    });

    u32 longest_prefix_match = 0;
    routing_table().for_each([&target, &matches, &longest_prefix_match, &chosen_route](auto& route) {
        if (route.destination.ip_address().to_u32() == 0 && matches(*route.adapter)) {
            dbgln_if(ROUTING_DEBUG, "Resorting to default route found for adapter: {}", route.adapter->name());
            chosen_route = route;
        }

        // We have a direct match and we can exit the routing table earlier.
        if (target == route.destination.ip_address()) {
            dbgln_if(ROUTING_DEBUG, "Target address has a direct match in the routing table");
            chosen_route = route;
            return;
        }

        if (route.destination.contains(target) && (route.destination.ip_address().to_u32() != 0)) {
            auto prefix = route.destination.length();

            if (chosen_route && prefix == longest_prefix_match) {
                chosen_route = (route.destination.length() > chosen_route->destination.length()) ? route : chosen_route;
                dbgln_if(ROUTING_DEBUG, "Found a matching prefix match. Using longer netmask: {}", route.destination.length());
            }

            if (prefix > longest_prefix_match) {
                dbgln_if(ROUTING_DEBUG, "Found a longer prefix match - route: {}", route.destination.to_string());
                longest_prefix_match = prefix;
                chosen_route = route;
            }
        }
    });

    if (local_adapter) {
        for (auto address : local_adapter->ipv4_addresses()) {
            if (target == address.key)
                return { local_adapter, local_adapter->mac_address(), address.key };
        }
    }

    if (!local_adapter && !chosen_route) {
        dbgln_if(ROUTING_DEBUG, "Routing: Couldn't find a suitable adapter for route to {}", target);
        return { nullptr, {}, {} };
    }

    RefPtr<NetworkAdapter> adapter = nullptr;
    IPv4AddressCidr next_hop_ip = IPv4AddressCidr(IPv4Address(0), 0);
    IPv4AddressCidr source_address = IPv4AddressCidr(IPv4Address(0), 0);

    if (local_adapter) {
        auto local_subnet = IPv4AddressCidr(0, 0);
        for (auto address : local_adapter->ipv4_addresses()) {
            auto address_cidr = IPv4AddressCidr(address.key, address.value);
            if (address_cidr.contains(target))
                local_subnet = address_cidr;
        }

        dbgln_if(ROUTING_DEBUG, "Routing: Got adapter for route (direct): {} ({}) for {}",
            local_adapter->name(),
            local_subnet,
            target);

        adapter = local_adapter;
        next_hop_ip = IPv4AddressCidr(target, local_subnet.length());
        source_address = local_subnet;
    } else if (chosen_route && allow_using_gateway == AllowUsingGateway::Yes) {
        auto adapter_subnet = IPv4AddressCidr(0, 0);
        for (auto address : chosen_route->adapter->ipv4_addresses()) {
            auto address_cidr = IPv4AddressCidr(address.key, address.value);
            if (address_cidr.contains(target))
                adapter_subnet = address_cidr;
        }

        dbgln_if(ROUTING_DEBUG, "Routing: Got adapter for route (using gateway {}): {} ({}) for {}",
            chosen_route->gateway,
            chosen_route->adapter->name(),
            adapter_subnet,
            target);
        adapter = chosen_route->adapter;
        next_hop_ip = IPv4AddressCidr(chosen_route->gateway, adapter_subnet.length());
        source_address = adapter_subnet;
    } else {
        return { nullptr, {}, {} };
    }

    // If it's a broadcast, we already know everything we need to know.
    if (matches(adapter) && (target == IPv4Address(255, 255, 255, 255) ||  target == next_hop_ip.last_address_of_subnet())) {
        if (allow_broadcast == AllowBroadcast::Yes)
            return { adapter, { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, source_address.ip_address() };

        return { nullptr, {}, {} };
    }

    if (adapter == NetworkingManagement::the().loopback_adapter())
        return { adapter, adapter->mac_address(), source_address.ip_address() };

    if (IPv4AddressCidr(IPv4Address(224, 0, 0, 0), 4).contains(target))
        return { adapter, multicast_ethernet_address(target), source_address.ip_address() };

    {
        auto addr = arp_table().with([&](auto const& table) -> auto {
            return table.get(next_hop_ip.ip_address());
        });
        if (addr.has_value()) {
            dbgln_if(ARP_DEBUG, "Routing: Using cached ARP entry for {} ({})", next_hop_ip, addr.value().to_string());
            return { adapter, addr.value(), source_address.ip_address() };
        }
    }

    dbgln_if(ARP_DEBUG, "Routing: Sending ARP request via adapter {} for IPv4 address {}", adapter->name(), next_hop_ip);

    ARPPacket request;
    request.set_operation(ARPOperation::Request);
    request.set_target_hardware_address({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff });
    request.set_target_protocol_address(next_hop_ip.ip_address());
    request.set_sender_hardware_address(adapter->mac_address());
    request.set_sender_protocol_address(source_address.ip_address());
    adapter->send({ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, request);

    if (NetworkTask::is_current()) {
        // FIXME: Waiting for the ARP response from inside the NetworkTask would
        // deadlock, so let's hope that whoever called route_to() tries again in a bit.
        dbgln_if(ARP_DEBUG, "Routing: Not waiting for ARP response from inside NetworkTask, sent ARP request using adapter {} for {}", adapter->name(), target);
        return { nullptr, {}, {} };
    }

    Optional<MACAddress> addr;
    if (!Thread::current()->block<ARPTableBlocker>({}, next_hop_ip.ip_address(), addr).was_interrupted()) {
        if (addr.has_value()) {
            dbgln_if(ARP_DEBUG, "Routing: Got ARP response using adapter {} for {} ({})",
                adapter->name(),
                next_hop_ip,
                addr.value().to_string());
            return { adapter, addr.value(), {} };
        }
    }

    dbgln_if(ROUTING_DEBUG, "Routing: Couldn't find route using adapter {} for {}", adapter->name(), target);
    return { nullptr, {}, {} };
}

}
