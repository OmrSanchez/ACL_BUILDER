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

            if event == "--Add_Rule--":
                print("\nAdding Rule...")
                self.model.acl_type = values["--ACL_TYPE--"]
                self.model.acl_name = values["--ACL_NAME--"]
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
                    self.view.unlock_multiline()

                    if is_standard:
                        self.model.format_src_network()
                        self.model.name_acl()
                        self.model.build_standard_rule_map()

                        self.work_entries(values)
                    else:
                        self.model.format_src_network()
                        self.model.format_dest_network()
                        self.model.name_acl()
                        self.model.build_extended_rule_map()

                        self.work_entries(values)

                    self.preview_entries(values)

            if event == "--Add_Remark--":
                self.model.acl_type = values["--ACL_TYPE--"]
                self.model.acl_name = values["--ACL_NAME--"]
                self.model.src_remark = values["--SRC_REMARK--"]
                self.model.dest_remark = values["--DEST_REMARK--"]
                self.model.service = values["--SVC--"]

                self.view.lock_header_controls()
                self.model.name_acl()

                self.work_remarks(values)
                self.preview_entries(values)

            if event == "--Add_Deny--":
                self.model.acl_type = values["--ACL_TYPE--"]
                self.model.acl_name = values["--ACL_NAME--"]
                self.view.lock_header_controls()
                self.model.name_acl()
                self.model.append_deny()

                self.preview_entries(values)

            if event == "--NUMBERED_ENTRIES--":
                self.preview_entries(values)

            if event == "Save::--SAVE--":
                print(event)
                try:
                    self.model.in_rule_preview_multi = values["--IN_PREVIEW--"]
                    self.model.out_rule_preview_multi = values["--OUT_PREVIEW--"]

                    self.model.save_to_file()
                    self.view.window["--WHERE_OUTPUT--"].update(f"Output file: {self.model.acl_name}.txt", visible=True)
                except (OSError, ValueError):
                    self.view.window["--ERROR--"].update("Something went wrong. Save failed.")

            if event == "--IN_PREVIEW--" or event == "--OUT_PREVIEW--":
                self.model.update_list_user_manual_change(self.numbered, values["--IN_PREVIEW--"], values["--OUT_PREVIEW--"])

        self.view.window.close()

    def preview_entries(self, values):
        if self.numbered:
            multiline_text = self.view.get_multiline('in')
            self.model.in_entries.pop(0)
            for num, entry in enumerate(self.model.in_entries, 1):
                num *= 10
                self.view.refresh_previews(f" {num} {entry}")
            self.view.window['--IN_PREVIEW--'].update(f"{self.model.in_acl_name}\n {self.view.get_multiline("in")}")
        else:
            self.view.refresh_previews(self.model.in_entries)

    def work_entries(self, values):
        if values["--BOTH_IN_OUT--"]:
            self.model.build_dual_rule_entries()
            self.model.append_dual_entries()
            # self.model.enumerate_dual_entries()

        elif values["--IN_ONLY--"]:
            self.model.build_in_entry()
            self.model.append_in_entry()
            # self.model.enumerate_in_entries()

        elif values["--OUT_ONLY--"]:
            self.model.build_out_entry()
            self.model.append_out_entry()
            # self.model.enumerate_out_entries()

    def work_remarks(self, values):
        if values["--BOTH_IN_OUT--"]:
            self.model.build_dual_path_remark()
            self.model.append_dual_path_remark()
            self.model.enumerate_dual_entries()

        elif values["--IN_ONLY--"]:
            self.model.build_in_remark()
            self.model.append_in_remark()
            self.model.enumerate_in_entries()

        elif values["--OUT_ONLY--"]:
            self.model.build_out_remark()
            self.model.append_out_remark()
            self.model.enumerate_out_entries()






