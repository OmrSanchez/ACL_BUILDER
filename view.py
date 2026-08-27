import io, base64
import FreeSimpleGUI as sg
from PIL import Image

FONT      = ("Consolas", 11)
FONT_BOLD = ("Consolas", 11, "bold")
FONT_HDR  = ("Consolas", 12, "bold")

HDR_COLOR  = "#185fa5"     # accent blue section titles
CARD_BG    = "#f4f6f8"     # light card tint
SRC_BG     = "#e1f5ee"     # green tint  (source)
SRC_FG     = "#0f6e56"
DST_BG     = "#e6f1fb"     # blue tint   (destination)
DST_FG     = "#185fa5"
NEUTRAL_BG = "#e4e6e9"     # grey tint   (neutral tags)
NEUTRAL_FG = "#5a5a5a"

def image_byte(png_path, size=(20, 20)):
    image = Image.open(png_path).resize(size, Image.LANCZOS)
    bio = io.BytesIO()
    image.save(bio, format='PNG')
    return base64.b64encode(bio.getvalue())

servers_img = image_byte("images/servers.png")
left_arrow  = image_byte("images/left-arrow.png")
router_blue = image_byte("images/router_blue.png")
right_arrow = image_byte("images/right-arrow.png")
isp_image   = image_byte("images/isp.png")

def tag(text, width=6, bg=NEUTRAL_BG, fg=NEUTRAL_FG):
    return sg.Text(text, size=(width, 1), justification="center", pad=(2, 2),
                   relief=sg.RELIEF_SUNKEN, border_width=1,
                   background_color=bg, text_color=fg, font=FONT)

def field(default="", width=14, key=None):
    return sg.InputText(default_text=default, size=(width, 1), pad=(2, 2), font=FONT, key=key)

def combo(values, default, width, key):
    return sg.Combo(values, default_value=default, readonly=True,
                    size=(width, 1), pad=(2, 2), font=FONT, key=key)

def header(text):
    return sg.Text(text, font=FONT_HDR, text_color=HDR_COLOR, pad=(0, 0))

def add_btn(text, key):
    return sg.Button(text, key=key, font=FONT_BOLD)

sg.theme("LightGrey1")

menu = [['&File', ['&Open::open', '&Save::--SAVE--']]]

settings_bar = [[
    sg.Text("Type", font=FONT_BOLD),
    combo(["Standard", "Extended"], "Extended", 12, "--ACL_TYPE--"),
    sg.Text("Name", font=FONT_BOLD),
    field("NAME_HERE", 28, "--ACL_NAME--"),
    sg.Push(),
    sg.Radio('Both', group_id=1, default=True, enable_events=True, key="--BOTH_IN_OUT--", font=FONT_BOLD),
    sg.Radio('In', group_id=1, enable_events=True, key="--IN_ONLY--", font=FONT_BOLD),
    sg.Radio('Out', group_id=1, enable_events=True, key="--OUT_ONLY--", font=FONT_BOLD),
    sg.Text("   "),
    sg.Checkbox("Numbered", default=False, key="--NUMBERED_ENTRIES--", enable_events=True, font=FONT),
]]

rule_card = [
    [header("Rule"), sg.Push(), add_btn("+ Add rule", "--Add_Rule--")],
    [
        combo(['permit', 'deny'], 'permit', 8, "--ACTION--"),
        combo(['ip', 'tcp', 'udp', 'icmp'], 'ip', 6, "--PROTOCOL--"),
        tag("Src:", 5, SRC_BG, SRC_FG),
        field('192.168.1.1', 14, "--SRC_IP--"),
        field('24', 4, "--SRC_MASK--"),
        combo(['eq', 'neq', 'gt', 'lt', 'range'], 'eq', 6, "--SRC_PO--"),
        field('', 18, "--SRC_PORT--"),
        tag("Dest:", 5, DST_BG, DST_FG),
        field("192.168.2.1", 14, "--DEST_IP--"),
        field("24", 4, "--DEST_MASK--"),
        combo(['eq', 'neq', 'gt', 'lt', 'range'], 'eq', 6, "--DEST_PO--"),
        field('', 18, "--DEST_PORT--"),
    ],
]

remark_card = [
    [header("Remark"), sg.Push(), add_btn("+ Add remark", "--Add_Remark--")],
    [
        tag('remark', 6), tag("*****", 5), tag('Allow', 5),
        field('LID/FAC1', 12, "--SRC_REMARK--"),
        tag("to", 3),
        field('LID/FAC2', 12, "--DEST_REMARK--"),
        field('Service', 12, "--SVC--"),
        tag('*****', 5),
    ],
]

action_strip = [[
    sg.Button("+ Add deny", key="--Add_Deny--", font=FONT_BOLD),
    sg.Text("", key="--WHERE_OUTPUT--", text_color='green', font=FONT_BOLD, visible=False),
    sg.Push(),
    sg.Text('', key='--ERROR--', text_color='red', font=FONT_BOLD, visible=False)
]]

in_pane = [
    [
        tag("IN", 4, DST_BG, DST_FG),
        sg.Image(data=servers_img), sg.Image(data=right_arrow),
        sg.Image(data=router_blue), sg.Image(data=right_arrow),
        sg.Image(data=isp_image), sg.Push(),
    ],
    [sg.Multiline("(IN PREVIEW) Name your ACL and add rules..", key="--IN_PREVIEW--",
                  font=FONT, autoscroll=True, expand_x=True, expand_y=True, enable_events=True, disabled=True)],
]
out_pane = [
    [
        sg.Push(),
        sg.Image(data=servers_img), sg.Image(data=left_arrow),
        sg.Image(data=router_blue), sg.Image(data=left_arrow),
        sg.Image(data=isp_image),
        tag('OUT', 4, DST_BG, DST_FG),
    ],
    [sg.Multiline("(OUT PREVIEW) Name your ACL and add rules..", key="--OUT_PREVIEW--",
                  font=FONT, autoscroll=True, expand_x=True, expand_y=True, enable_events=True, disabled=True)],
]

class View:
    def __init__(self):
        self.layout = [
            [sg.Menu(menu, key="--MENU--")],
            [sg.Frame("", settings_bar, expand_x=True, relief=sg.RELIEF_FLAT, pad=(4, 4))],
            [sg.Frame("", rule_card, expand_x=True, background_color=CARD_BG,
                      relief=sg.RELIEF_GROOVE, border_width=1, pad=(4, 4))],
            [sg.Frame("", remark_card, expand_x=True, background_color=CARD_BG,
                      relief=sg.RELIEF_GROOVE, border_width=1, pad=(4, 4))],
            [sg.Column(in_pane, expand_x=True, expand_y=True),
             sg.Column(out_pane, expand_x=True, expand_y=True)],
            [sg.Column(action_strip, expand_x=True, pad=(4, 0))],
        ]
        self.window = sg.Window("ACL Builder", self.layout, resizable=True,
                                font=FONT, finalize=True)
        self.window.set_min_size((1150, 600))

    def lock_header_controls(self):
        self.window["--ACL_NAME--"].update(readonly=True, background_color="gray")
        self.window["--ACL_TYPE--"].update(disabled=True)

    def unlock_multiline(self):
        self.window['--IN_PREVIEW--'].update(disabled=False)
        self.window['--OUT_PREVIEW--'].update(disabled=False)

    def update_error_msg(self, text):
        self.window["--ERROR--"].update(text, visible=True)

    def refresh_previews(self, in_entries_string, out_entries_string):
        self.window["--IN_PREVIEW--"].update("\n".join(in_entries_string))
        self.window["--OUT_PREVIEW--"].update("\n".join(out_entries_string))

    def get_event(self):
        return self.window.read()

    def close(self):
        self.window.close()