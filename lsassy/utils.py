from netaddr import IPAddress, IPRange, IPNetwork, AddrFormatError
import os


def is_valid_ip(ip):
    """
    Check if IP address is valid
    :param ip: IP address
    :return: Is valid
    """
    ip = ip.split(".")
    if len(ip) != 4:
        return False
    return all([0 <= int(t) <= 255 for t in ip])


def get_log_max_spaces(targets):
    """
    Padding utility for targets
    :param targets: List of targets
    :return: Padding size
    """
    return max(len(t) for t in targets) + 4


def get_log_spaces(target, spaces):
    """
    Get padding for a specific host when displayed to user
    :param target: Host
    :param spaces: Total padding
    :return: Padding for specific host
    """
    return spaces - len(target)


def parse_targets(target):
    """
    Parse provided targets
    :param target: Targets
    :return: List of IP addresses
    """
    if '-' in target:
        ip_range = target.split('-')
        try:
            t = IPRange(ip_range[0], ip_range[1])
        except AddrFormatError:
            try:
                start_ip = IPAddress(ip_range[0])

                start_ip_words = list(start_ip.words)
                start_ip_words[-1] = ip_range[1]
                start_ip_words = [str(v) for v in start_ip_words]

                end_ip = IPAddress('.'.join(start_ip_words))

                t = IPRange(start_ip, end_ip)
            except AddrFormatError:
                t = target
    else:
        try:
            t = IPNetwork(target)
        except AddrFormatError:
            t = target
    if type(t) == IPNetwork or type(t) == IPRange:
        return list(t)
    else:
        return [t.strip()]


def get_targets(targets):
    """
    Get targets from file or string
    :param targets: List of targets
    :return: List of IP addresses
    """
    ret_targets = []
    for target in targets:
        if os.path.exists(target):
            with open(target, 'r') as target_file:
                for target_entry in target_file:
                    ret_targets += parse_targets(target_entry)
        else:
            ret_targets += parse_targets(target)
    return [str(ip) for ip in ret_targets]