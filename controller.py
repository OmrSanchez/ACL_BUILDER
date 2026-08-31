import FreeSimpleGUI as sg

from model import Model
from view import View

SOURCE = "Source"
DESTINATION = "Destination"

class Controller:
    def __init__(self, view, model):
        self.view = view
        self.model = model
        self.window = None
        self.numbered = False

        self.error = ""

    def run(self):
        while True:
            event, values = self.view.get_event()

            if event == sg.WIN_CLOSED or event == "Exit":
                break

            self.numbered = values["--NUMBERED_ENTRIES--"]

            if event == "--Set_Name--":
                self.model.acl_type = values["--ACL_TYPE--"]
                self.model.acl_name = values["--ACL_NAME--"]
                self.view.window["--IN_PREVIEW--"].update(self.model.build_first_acl_in_entry())
                self.view.window["--OUT_PREVIEW--"].update(self.model.build_first_acl_out_entry())
                self.view.lock_header_controls()
                self.view.unlock_rule_entry_controls()

            if event == "--Add_Rule--":
                print("\nAdding Rule...")
                self.model.action = values["--ACTION--"]
                self.model.protocol = values["--PROTOCOL--"]
                self.model.src_ip = values["--SRC_IP--"]
                self.model.src_mask = values["--SRC_MASK--"]
                self.model.src_port_option = values["--SRC_PO--"]
                self.model.src_port = values["--SRC_PORT--"]
                self.model.dest_ip = values["--DEST_IP--"]
                self.model.dest_mask = values["--DEST_MASK--"]
                self.model.dest_port = values["--DEST_PORT--"]
                self.model.dest_port_option = values["--DEST_PO--"]

                is_standard = self.model.acl_type == "Standard"

                src_valid_ports = self.model.validate_user_input_ports(SOURCE)
                dest_valid_ports = self.model.validate_user_input_ports(DESTINATION)
                src_valid_ip = self.model.validate_user_input_ip(SOURCE)
                src_valid_mask = self.model.validate_user_input_mask(SOURCE)
                dest_valid_ip = self.model.validate_user_input_ip(DESTINATION)
                dest_valid_mask = self.model.validate_user_input_mask(DESTINATION)

                if not src_valid_ports:
                    self.view.update_error_msg("Source port validation failed")
                    print("Source port validation failed")
                elif not dest_valid_ports:
                    self.view.update_error_msg("Destination port validation failed")
                    print("Destination port validation failed")
                elif not src_valid_ip:
                    self.view.update_error_msg("Source ip validation failed")
                    print("Source ip validation failed")
                elif not dest_valid_ip:
                    self.view.update_error_msg("Destination ip validation failed")
                    print("Destination ip validation failed")
                elif not src_valid_mask:
                    self.view.update_error_msg("Src Mask validation failed")
                    print("Src Mask validation failed")
                elif not dest_valid_mask:
                    self.view.update_error_msg("Dest Mask validation failed")
                    print("Dest Mask validation failed")
                else:
                    print('IPs are valid. Proceeding to add ACL entry...')
                    self.view.lock_header_controls()
                    self.view.unlock_rule_entry_controls()
                    self.view.unlock_numbered()

                    if is_standard:
                        self.model.format_src_network()
                        self.model.build_standard_rule_map()
                        self.work_entries(values)
                    else:
                        self.model.format_src_network()
                        self.model.format_dest_network()
                        self.model.build_extended_rule_map()
                        self.work_entries(values)

            if event == "--Add_Remark--":
                self.model.src_remark = values["--SRC_REMARK--"]
                self.model.dest_remark = values["--DEST_REMARK--"]
                self.model.service = values["--SVC--"]
                self.view.lock_header_controls()
                self.work_remarks(values)

            if event == "--Add_Deny--":
                self.model.acl_type = values["--ACL_TYPE--"]
                self.model.acl_name = values["--ACL_NAME--"]
                self.view.lock_header_controls()
                self.work_denies(values)

            if event == "--NUMBERED_ENTRIES--":
                if values['--NUMBERED_ENTRIES--']:
                    self.number_entries()
                if not values['--NUMBERED_ENTRIES--']:
                    self.view.remove_number_entries(self.model.build_first_acl_in_entry(), self.model.build_first_acl_out_entry())

            if event == "Save::--SAVE--":
                try:
                    self.model.save_to_file()
                    self.view.window["--WHERE_OUTPUT--"].update(f"Output file: {self.model.acl_name}.txt", visible=True)
                except (OSError, ValueError):
                    self.view.window["--ERROR--"].update("Something went wrong. Save failed.")

            # if event == "--IN_PREVIEW--":
            #   in_multiline = self.view.window["
            # or event == "--OUT_PREVIEW--":
            #     self.model.update_list_user_manual_change(self.numbered, values["--IN_PREVIEW--"], values["--OUT_PREVIEW--"])

        self.view.window.close()

    def work_entries(self, values):
        if values["--BOTH_IN_OUT--"]:
            self.model.build_in_entry()
            self.view.update_in(self.model.in_entry)
            self.model.build_out_entry()
            self.view.update_out(self.model.out_entry)

        elif values["--IN_ONLY--"]:
            self.model.build_in_entry()
            self.view.update_in(self.model.in_entry)

        elif values["--OUT_ONLY--"]:
            self.model.build_out_entry()
            self.view.update_out(self.model.out_entry)

    def work_remarks(self, values):
        if values["--BOTH_IN_OUT--"]:
            self.model.build_in_remark()
            self.view.update_in(self.model.in_remark)
            self.model.build_out_remark()
            self.view.update_out(self.model.out_remark)

        elif values["--IN_ONLY--"]:
            self.model.build_in_remark()
            self.view.update_in(self.model.in_remark)

        elif values["--OUT_ONLY--"]:
            self.model.build_out_remark()
            self.view.update_out(self.model.out_remark)

    def work_denies(self, values):
        if values["--BOTH_IN_OUT--"]:
            self.view.update_in(self.model.deny_entry)
            self.view.update_out(self.model.deny_entry)

        elif values["--IN_ONLY--"]:
            self.view.update_in(self.model.deny_entry)

        elif values["--OUT_ONLY--"]:
            self.view.update_out(self.model.deny_entry)

    def number_entries(self):
        self.view.number_entries(self.model.build_first_acl_in_entry(), self.model.build_first_acl_out_entry())




