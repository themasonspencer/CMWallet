from sd_jwt.common import SDObj

def build_claims(paths: dict):
    user_claims = {}
    for path_name, path_value in paths.items():
        if path_name == "_sd":
            continue
        elif "value" not in path_value and "display" not in path_value:
            sd = path_value["_sd"]
            if sd:
                user_claims[SDObj(path_name)] = build_claims(path_value)
            else:
                user_claims[path_name] = build_claims(path_value)
        else:
            sd = path_value["_sd"]
            if sd:
                user_claims[SDObj(path_name)] = path_value["value"]
            else:
                user_claims[path_name] = path_value["value"]
    return user_claims

def build_claims_for_display(out: list, paths: dict, curr_path: list):
    for path_name, path_value in paths.items():
        if path_name == "_sd":
            continue
        new_path = curr_path.copy()
        new_path.append(path_name)
        if "value" not in path_value:
            build_claims_for_display(out, path_value, new_path)
        elif "display" in path_value:
            display = {"locale": "en-US"}
            display["name"] = path_value["display"]
            display = [display]
            claim = {}
            claim["path"] = new_path
            claim["display"] = display
            out.append(claim)