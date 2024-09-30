/*
 * Copyright (c) 2022, Liav A. <liavalb@hotmail.co.il>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/JsonObjectSerializer.h>
#include <Kernel/FileSystem/SysFS/Subsystems/Kernel/Network/Adapters.h>
#include <Kernel/Net/NetworkingManagement.h>
#include <Kernel/Sections.h>
#include <AK/IpAddressCidr.h>

namespace Kernel {

UNMAP_AFTER_INIT SysFSNetworkAdaptersStats::SysFSNetworkAdaptersStats(SysFSDirectory const& parent_directory)
    : SysFSGlobalInformation(parent_directory)
{
}

UNMAP_AFTER_INIT NonnullRefPtr<SysFSNetworkAdaptersStats> SysFSNetworkAdaptersStats::must_create(SysFSDirectory const& parent_directory)
{
    return adopt_ref_if_nonnull(new (nothrow) SysFSNetworkAdaptersStats(parent_directory)).release_nonnull();
}

ErrorOr<void> SysFSNetworkAdaptersStats::try_generate(KBufferBuilder& builder)
{
    auto array = TRY(JsonArraySerializer<>::try_create(builder));
    TRY(NetworkingManagement::the().try_for_each([&array](auto& adapter) -> ErrorOr<void> {
        auto obj = TRY(array.add_object());
        TRY(obj.add("name"sv, adapter.name()));
        TRY(obj.add("class_name"sv, adapter.class_name()));
        auto mac_address = TRY(adapter.mac_address().to_string());
        TRY(obj.add("mac_address"sv, mac_address->view()));

        auto ipv4_addresses = adapter.ipv4_addresses();
        if (!ipv4_addresses.is_empty()) {
            auto ipv4_addresses_obj = TRY(obj.add_array("ipv4_addresses"sv));

            for (auto ipv4_address : ipv4_addresses) {
                auto ipv4_address_cidr = IPv4AddressCidr(ipv4_address.key, ipv4_address.value);
                auto ipv4_address_string = TRY(ipv4_address_cidr.to_string());
                TRY(ipv4_addresses_obj.add(ipv4_address_string->view()));
            }

            TRY(ipv4_addresses_obj.finish());
        }

        auto ipv6_addresses = adapter.ipv6_addresses();
        if (!ipv6_addresses.is_empty()) {
            auto ipv6_addresses_obj = TRY(obj.add_array("ipv6_addresses"sv));

            for (auto ipv6_address : ipv6_addresses) {
                auto ipv6_address_cidr = IPv6AddressCidr(ipv6_address.key, ipv6_address.value);
                auto ipv6_address_string = TRY(ipv6_address_cidr.to_string());
                TRY(ipv6_addresses_obj.add(ipv6_address_string->view()));
            }

            TRY(ipv6_addresses_obj.finish());
        }

        TRY(obj.add("packets_in"sv, adapter.packets_in()));
        TRY(obj.add("bytes_in"sv, adapter.bytes_in()));
        TRY(obj.add("packets_out"sv, adapter.packets_out()));
        TRY(obj.add("bytes_out"sv, adapter.bytes_out()));
        TRY(obj.add("link_up"sv, adapter.link_up()));
        TRY(obj.add("link_speed"sv, adapter.link_speed()));
        TRY(obj.add("link_full_duplex"sv, adapter.link_full_duplex()));
        TRY(obj.add("mtu"sv, adapter.mtu()));
        TRY(obj.add("packets_dropped"sv, adapter.packets_dropped()));
        TRY(obj.finish());
        return {};
    }));
    TRY(array.finish());
    return {};
}

}
