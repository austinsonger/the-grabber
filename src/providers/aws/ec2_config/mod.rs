mod ec2_instance;
mod route_table;
mod security_group;
mod vpc;

pub use ec2_instance::Ec2InstanceConfigCollector;
pub use route_table::RouteTableConfigCollector;
pub use security_group::SecurityGroupConfigCollector;
pub use vpc::VpcConfigCollector;

pub(super) fn fmt_ip_perm(perms: &[aws_sdk_ec2::types::IpPermission]) -> String {
    perms
        .iter()
        .map(|p| {
            let proto = p.ip_protocol().unwrap_or("-1");
            let from = p
                .from_port()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "All".to_string());
            let to = p
                .to_port()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "All".to_string());
            let cidrs: Vec<&str> = p.ip_ranges().iter().filter_map(|r| r.cidr_ip()).collect();
            let ipv6: Vec<&str> = p
                .ipv6_ranges()
                .iter()
                .filter_map(|r| r.cidr_ipv6())
                .collect();
            let sgs: Vec<String> = p
                .user_id_group_pairs()
                .iter()
                .filter_map(|g| g.group_id().map(|s| s.to_string()))
                .collect();
            let mut sources = cidrs;
            sources.extend(ipv6.iter().copied());
            let mut combined: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
            combined.extend(sgs);
            format!("{proto}:{from}-{to}:[{}]", combined.join(","))
        })
        .collect::<Vec<_>>()
        .join("; ")
}
