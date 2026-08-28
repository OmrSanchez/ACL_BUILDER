from ip_address_helper import port_segment, is_valid_ip, check_text_mask, sanitize_address, finalize_network, is_compatible_port
from write_read_helper import save_to_file
import re

class Model:
    def __init__(self):
        self.deny_entry = "deny ip any any"

        self.acl_name = ""
        self.acl_type = ""
        self.action = ""
        self.protocol = ""
        self.sanitized_src_acl_address = ""
        self.src_target = ""
        self.sanitized_dest_acl_address = ""
        self.dest_target = ""

        self.rule = ""

        self.src_ip = ""
        self.src_mask = ""
        self.src_network = ""
        self.src_port_option = ""
        self.src_port = ""
        self.in_entry = ""

        self.dest_ip = ""
        self.dest_mask = ""
        self.dest_network = ""
        self.dest_port_option = ""
        self.dest_port = ""
        self.out_entry = ""

        self.in_acl_name = ""
        self.out_acl_name = ""

        self.src_remark = ""
        self.dest_remark = ""
        self.service = ""

        self.in_remark = ""
        self.out_remark: str= ""

        self.error_msg: str = ""

    def incurred_error(self, msg: str):
        self.error_msg = msg

    def validate_user_input_ports(self, field_name):
        print("Validate User Input Ports: Running port validation...")
        if field_name == "Source":
            print(f"Validating ports for {field_name}")
            if not self.src_port.strip():
                print("No ports detected")
                return True
            else:
                src_ports = self.src_port.split()
                if len(src_ports) > 10:
                    print("Error: Too many ports. Allowed max of 10")
                    return False
                else:
                    print("There are less than 10 ports. Inspecting each port individually")
                    for port in src_ports:
                        print(f"Inspecting port: {port}")
                        compatible = is_compatible_port(port)
                        if not compatible:
                             return False
                    return True

        elif field_name == "Destination":
            print(f"Validating ports for {field_name}")
            if not self.dest_port.strip():
                print("No ports detected.")
                return True
            else:
                dest_ports = self.dest_port.split()
                if len(dest_ports) > 10:
                    print("Error: Too many ports. Allowed max of 10")
                    return False
                else:
                    print("There are less than 10 ports. Inspecting each port individually")
                    for port in dest_ports:
                        print(f"Inspecting port: {port}")
                        compatible = is_compatible_port(port)
                        if not compatible:
                            return False
                    return True

    def validate_user_input_ip(self, field_name):
        if field_name == "Source":
            if self.src_ip.lower() == "any":
                print(f"Source passed ip validate")
                return True
            else:
                print(f"Source passed ip validate")
                return is_valid_ip(self.src_ip)
        elif field_name == "Destination":
            if self.dest_ip.lower() == "any":
                print(f"Dest passed ip validate")
                return True
            else:
                print(f"Dest passed ip validate")
                return is_valid_ip(self.dest_ip)
        else:
            return False

    def validate_user_input_mask(self, field_name):
        if field_name == "Source":
            if self.src_mask:
                print(f"Source has a mask. {self.src_mask} Checking it..")
                return check_text_mask(self.src_mask)
            else:
                print(f"Source does not have a mask. Handling as a host..")
                return True
        elif field_name == "Destination":
            if self.dest_mask:
                print(f"Dest has a mask. {self.dest_mask} Checking it..")
                return check_text_mask(self.dest_mask)
            else:
                print(f"Dest does not have a mask. Handling as a host..")
                return True
        else:
            return False

    def format_src_network(self):
        print("Running Source format..")
        if self.src_ip.lower() == 'any':
            self.src_target = "any"
        else:
            network = self.src_ip + self.src_mask
            if "/" not in network:
                self.src_network = sanitize_address(self.src_ip, self.src_mask)
                self.src_target = finalize_network(self.src_network)
            else:
                self.src_network = network
                self.src_target = finalize_network(self.src_network)

    def format_dest_network(self):
        print("Running Dest format")
        if self.dest_ip.lower() == 'any':
            self.dest_target = "any"
        else:
            if "/" not in (self.dest_ip+self.dest_mask):
                self.dest_network = sanitize_address(self.dest_ip, self.dest_mask)
                self.dest_target = finalize_network(self.dest_network)
            else:
                self.dest_network = self.dest_ip+self.dest_mask
                self.dest_target = finalize_network(self.dest_network)

    def build_standard_rule_map(self):
        self.rule = {"action": self.action, "protocol": "", "source": self.src_target,
                "destination": "", "src_port_option": "", "src_port": "",
                "dest_port_option": "", "dest_port": ""}

    def build_extended_rule_map(self):
        self.rule = {"action": self.action, "protocol": self.protocol,
                "source": self.src_target, "destination": self.dest_target,
                "src_port_option": self.src_port_option, "src_port": self.src_port.strip(),
                "dest_port_option": self.dest_port_option, "dest_port": self.dest_port.strip()}

    def build_in_entry(self):
        action, protocol = self.rule["action"], self.rule["protocol"]
        source, destination = self.rule["source"], self.rule["destination"]
        src_port = port_segment(self.rule.get("src_port_option", ""), self.rule.get("src_port", ""))
        dest_port = port_segment(self.rule.get("dest_port_option", ""), self.rule.get("dest_port", ""))

        if protocol == "":
            line = " ".join(p for p in [action, source] if p)
            self.in_entry = line

        in_entry_parts = [action, protocol, source, src_port, destination, dest_port]
        self.in_entry = " ".join(p for p in in_entry_parts if p)

    def build_out_entry(self):
        action, protocol = self.rule["action"], self.rule["protocol"]
        source, destination = self.rule["source"], self.rule["destination"]
        src_port = port_segment(self.rule.get("src_port_option", ""), self.rule.get("src_port", ""))
        dest_port = port_segment(self.rule.get("dest_port_option", ""), self.rule.get("dest_port", ""))

        if protocol == "":
            line = " ".join(p for p in [action, source] if p)
            self.out_entry = line

        out_entry_parts = [action, protocol, destination, dest_port, source, src_port]
        self.out_entry = " ".join(p for p in out_entry_parts if p)

    def build_in_remark(self):
        self.in_remark = f"remark ***** PERMIT {self.src_remark.upper()} to {self.dest_remark.upper()} {self.service.upper()} *****"

    def build_out_remark(self):
        self.out_remark = f"remark ***** PERMIT {self.dest_remark.upper()} to {self.src_remark.upper()} {self.service.upper()} *****"

    def build_first_acl_in_entry(self):
        kind = "standard" if self.acl_type == "Standard" else "extended"
        name = re.sub(r'[^a-zA-Z0-9]+', '_', self.acl_name).strip('_')
        return f"ip access-list {kind} {name.upper()}_IN\n"

    def build_first_acl_out_entry(self):
        kind = "standard" if self.acl_type == "Standard" else "extended"
        name = re.sub(r'[^a-zA-Z0-9]+', '_', self.acl_name).strip('_')
        return f"ip access-list {kind} {name.upper()}_OUT\n"

    def save_to_file(self):
        save_to_file(self.acl_name, self.in_rule_preview_multi, self.out_rule_preview_multi)