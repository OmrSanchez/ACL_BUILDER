def save_to_file(acl_name, rules_for_in, rules_for_out):
    with open(f"{acl_name}.txt", 'w', encoding="utf-8") as file:
        file.writelines(rules_for_in + "\n\n" + rules_for_out)