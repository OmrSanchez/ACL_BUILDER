from ip_address_helper import port_segment, is_valid_ip, check_text_mask, sanitize_address, finalize_network
from write_read_helper import save_to_file

class Model:
    def __init__(self):
        self.src_port = ""
        self.dest_port = ""
        self.acl_name = ""
        self.acl_type = ""
        self.action = ""
        self.protocol = ""
        self.sanitized_src_acl_address = ""
        self.src_target = ""
        self.sanitized_dest_acl_address = ""
        self.dest_target = ""

        self.src_ip = ""
        self.src_mask = ""
        self.src_network = ""

        self.src_port_option = ""

        self.dest_ip = ""
        self.dest_mask = ""
        self.dest_network = ""

        self.dest_port_option = ""
        self.rule = ""
        self.in_entry = ""
        self.out_entry = ""
        self.in_acl_name = ""
        self.out_acl_name = ""
        self.in_entries = []
        self.out_entries = []
        self.in_numbered_entries = []
        self.out_numbered_entries = []
        self.in_numbers = 0
        self.out_numbers = 0
        self.src_remark = ""
        self.dest_remark = ""
        self.service = ""
        self.in_remark = ""
        self.out_remark: str= ""
        self.error_msg: str = ""

        self.in_rule_preview_multi = ""
        self.out_rule_preview_multi = ""

    def incurred_error(self, msg: str):
        self.error_msg = msg

    def validate_ports(self, field_name):
        if field_name == "Source":
            if not self.src_port.strip():
                return None
            src_ports = self.src_port.split()
            if len(src_ports) > 10:
                self.error_msg = f"Source Port: maximum of 10 ports per line"
            if not all(p.isdigit() for p in src_ports):
                self.error_msg =  f"Source Port: ports must be numbers separated by spaces"

        if field_name == "Destination":
            dest_raw = self.dest_port.strip()
            if not dest_raw:
                return None
            dest_ports = dest_raw.split()
            if len(dest_ports) > 10:
                return f"Destination Port: maximum of 10 ports per line"
            if not all(p.isdigit() for p in dest_ports):
                return f"Destination Port: ports must be numbers separated by spaces"
        return None

    def validate_user_input_ip(self, field_name):
        if field_name == "Source":
            if self.src_ip.lower() == "any":
                print(f"Source passed ip validate")
                return True
            else:
                print(f"Source passed ip validate")
                return is_valid_ip(self.src_ip)

        if field_name == "Destination":
            if self.dest_ip.lower() == "any":
                print(f"Dest passed ip validate")
                return True
            else:
                print(f"Dest passed ip validate")
                return is_valid_ip(self.dest_ip)

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
                "destination": "", "src_port_operator": "", "src_port": "",
                "dest_port_operator": "", "dest_port": ""}

    def build_extended_rule_map(self):
        self.rule = {"action": self.action, "protocol": self.protocol,
                "source": self.src_target, "destination": self.dest_target,
                "src_port_option": self.src_port_option, "src_port": self.src_port.strip(),
                "dest_port_option": self.dest_port_option, "dest_port": self.dest_port.strip()}

    def build_dual_rule_entries(self):
        action, protocol = self.rule["action"], self.rule["protocol"]
        source, destination = self.rule["source"], self.rule["destination"]
        src_port = port_segment(self.rule.get("src_port_option", ""), self.rule.get("src_port", ""))
        dest_port = port_segment(self.rule.get("dest_port_option", ""), self.rule.get("dest_port", ""))
        if protocol == "":
            line = " ".join(p for p in [action, source] if p)
            self.in_entry = line
            self.out_entry = line

        in_entry_parts = [action, protocol, source, src_port, destination, dest_port]
        out_entry_parts = [action, protocol, destination, dest_port, source, src_port]
        self.in_entry = " ".join(p for p in in_entry_parts if p)
        self.out_entry = " ".join(p for p in out_entry_parts if p)

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
        src_port = port_segment(self.rule.get("src_port_operator", ""), self.rule.get("src_port", ""))
        dest_port = port_segment(self.rule.get("dest_port_operator", ""), self.rule.get("dest_port", ""))

        if protocol == "":
            line = " ".join(p for p in [action, source] if p)
            self.out_entry = line

        out_entry_parts = [action, protocol, destination, dest_port, source, src_port]
        self.out_entry = " ".join(p for p in out_entry_parts if p)

    def append_in_entry(self):
        self.append_acl_name_dual()
        self.in_entries.append(f" {self.in_entry}")

    def append_out_entry(self):
        self.append_acl_name_dual()
        self.out_entries.append(f" {self.out_entry}")

    def append_dual_entries(self):
        self.append_in_entry()
        self.append_out_entry()

    def name_acl(self):
        kind = "standard" if self.acl_type == "Standard" else "extended"
        self.in_acl_name = f"ip access-list {kind} {self.acl_name}_IN"
        self.out_acl_name = f"ip access-list {kind} {self.acl_name}_OUT"

    def append_in_remark(self):
        self.append_acl_name_dual()
        self.in_entries.append(f" {self.in_remark}")

    def append_out_remark(self):
        self.append_acl_name_dual()
        self.out_entries.append(f" {self.out_remark}")

    def append_dual_path_remark(self):
        self.append_in_remark()
        self.append_out_remark()

    def append_acl_name_dual(self):
        if self.in_acl_name not in self.in_entries:
            self.in_entries.append(self.in_acl_name)
        if self.out_acl_name not in self.out_entries:
            self.out_entries.append(self.out_acl_name)

    def build_in_remark(self):
        self.in_remark = f"remark ***** ALLOW {self.src_remark} to {self.dest_remark} {self.service.upper()} *****"

    def build_out_remark(self):
        self.out_remark = f"remark ***** ALLOW {self.dest_remark} to {self.src_remark} {self.service.upper()} *****"

    def build_dual_path_remark(self):
        self.build_in_remark()
        self.build_out_remark()

    def append_deny(self):
        self.append_acl_name_dual()
        self.in_entries.append(" deny ip any any")
        self.out_entries.append(" deny ip any any")
        self.enumerate_dual_entries()

    def in_number_add(self, number):
        self.in_numbers = self.in_numbers + number

    def out_number_add(self, number):
        self.out_numbers = self.out_numbers + number

    def enumerate_in_entries(self):
        if self.in_acl_name not in self.in_numbered_entries:
            self.in_numbered_entries.insert(0, self.in_acl_name)
        entry = self.in_entries[-1]
        if entry is not self.in_acl_name:
            self.in_number_add(10)
            numbered_entry = f" {self.in_numbers}{entry}"
            self.in_numbered_entries.append(numbered_entry)

    def enumerate_out_entries(self):
        if self.out_acl_name not in self.out_numbered_entries:
            self.out_numbered_entries.insert(0, self.out_acl_name)
        entry = self.out_entries[-1]
        if entry is not self.out_acl_name:
            self.out_number_add(10)
            numbered_entry = f" {self.out_numbers}{entry}"
            self.out_numbered_entries.append(numbered_entry)

    def enumerate_dual_entries(self):
        self.enumerate_in_entries()
        self.enumerate_out_entries()

    def save_to_file(self):
        save_to_file(self.acl_name, self.in_rule_preview_multi, self.out_rule_preview_multi)

