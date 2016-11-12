__module_name__ = "gpg plugin"
__module_version__ = "0.1"
__module_description__ = ""

import hexchat
import subprocess
import shlex
import base64
import random

# Protocol :gpg:idnumber:data:end:
PGP_START=":gpg:"
PGP_END=":end:"
MAX_LEN=400 # unsauber, muss eigentlich berrechnet werden (siehe Konversations)

GPG_PATH="gpg2"

GREEN="03"
RED="04"

recipients = {}
messages = {}
gpg_off_channels = []

reload(

def print_msg(msg="", color="", begin=True, end=True):
    if begin:
        print("")
        print("----- gpg -----")
    if msg:
        msg = msg.replace("\n", "\n\003{}".format(color))
        print("\003{}{}".format(color,msg))
    if end:
        print("---------------")
        print("")

def strip_pgp(msg):
    if msg.startswith(PGP_START):
        return msg.lstrip(PGP_START)
    return ""

def split_send(raw_data, verb):
    encoded = base64.b64encode(raw_data).decode('utf-8')
    id = random.randint(0,1000)
    splitted = [encoded[i:i+MAX_LEN] for i in range(0, len(encoded), MAX_LEN)]
    for split in splitted[:-1]:
        command = "{} {}{}:{}".format(verb, PGP_START, id, split)
        hexchat.command(command)
    command = "{} {}{}:{}{}".format(verb, PGP_START, id, splitted[-1], PGP_END)
    hexchat.command(command)

# returns string
def decrypt(raw_data):
    cmd = '{} --quiet --batch --trust-model always'.format(GPG_PATH)
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    decrypted, err = p.communicate(raw_data)
    if err:
        print_msg(err.decode('utf-8'), color=RED)
    return decrypted.decode('utf-8')

# returns raw data
def encrypt(msg, recipients):
    cmd = '{} -e --batch --trust-model always'.format(GPG_PATH)
    for name in recipients:
        cmd += ' -r {} '.format(name.strip())

    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    encrypted_data, err = p.communicate(msg.encode())
    if err:
        hexchat.prnt(err.decode('utf-8'))
    return encrypted_data

def command_hook(word, word_eol, userdata):
    if word_eol[0].startswith(userdata):
        word_eol[0] = word_eol[0].lstrip(userdata + " ")
    if strip_pgp(word_eol[0]):
        return hexchat.EAT_NONE

    channel = hexchat.get_info("channel")
    if channel in gpg_off_channels:
        return hexchat.EAT_NONE
    if not channel in recipients:
        if not channel in messages:
            return hexchat.EAT_NONE
        
        print_msg("Messages on this channel should be encrypted.\nPlease choose recipient keys using the command /add_key <key>", RED)
        return hexchat.EAT_ALL
    if not recipients[channel]:
        print_msg("Messages on this channel should be encrypted.\nPlease choose recipient keys using the command /add_key <key>", RED)
        return hexchat.EAT_ALL

    if not recipients[channel][0].strip():
        print_msg("Messages on this channel should be encrypted.\nPlease choose recipient keys using the command /add_key <key>", RED)
        return hexchat.EAT_ALL 

    encrypted = encrypt(word_eol[0], recipients[channel])
    if not encrypted:
        print_msg("Something with the gpg2 encryption didn't work out...", color=RED)
        return hexchat.EAT_ALL
    split_send(encrypted, userdata)
    return hexchat.EAT_ALL

def try_decode(msg):
    global messages

    stripped = strip_pgp(msg)
    if stripped:
        id, stripped = stripped.split(":", 1)
        channel = hexchat.get_info("channel")

        if not channel in messages:
            messages[channel] = {}
        if not id in messages[channel]:
            messages[channel][id] = ""

        if stripped.endswith(PGP_END):
            total_msg = messages[channel][id] + stripped.rstrip(PGP_END)
            messages[channel][id] = ""
            decrypted = decrypt(base64.b64decode(total_msg))
            return (decrypted, hexchat.EAT_ALL)
        else:
            messages[channel][id] = messages[channel][id] + stripped
            return ("", hexchat.EAT_ALL)
    return("", hexchat.EAT_NONE)

def channel_msg_hook(word, word_eol, userdata):
    msg, return_code = try_decode(word[1])
    if msg:
        nick = hexchat.get_info("nick")
        if "@{}".format(nick) in msg:
            hilight = True
        else:
            hilight = False
        if len(word)>2:
            if hilight:
                hexchat.emit_print("Channel Msg Hilight", word[0], msg, word[2])
            else:
                hexchat.emit_print("Channel Message", word[0], msg, word[2])
        else:
            if hilight:
                hexchat.emit_print("Channel Msg Hilight", word[0], msg)
            else:
                hexchat.emit_print("Channel Message", word[0], msg)
    return return_code

def channel_action_hook(word, word_eol, userdata):
    msg, return_code = try_decode(word[1])
    if msg:
        nick = hexchat.get_info("nick")
        if "@{}".format(nick) in msg:
            hilight = True
        else:
            hilight = False
        if len(word)>2:
            if hilight:
                hexchat.emit_print("Channel Action Hilight", word[0], msg, word[2])
            else:
                hexchat.emit_print("Channel Action", word[0], msg, word[2])
        else:
            if hilight:
                hexchat.emit_print("Channel Action Hilight", word[0], msg)
            else:
                hexchat.emit_print("Channel Action", word[0], msg)
    return return_code

def your_message_hook(word, word_eol, userdata):
    msg, return_code = try_decode(word[1])
    if msg:
        if len(word)>2:
            hexchat.emit_print("Your Message", word[0], msg, word[2])
        else:
            hexchat.emit_print("Your Message", word[0], msg)
    return return_code

def your_action_hook(word, word_eol, userdata):
    msg, return_code = try_decode(word[1])
    if msg:
        if len(word)>2:
            hexchat.emit_print("Your Action", word[0], msg, word[2])
        else:
            hexchat.emit_print("Your Action", word[0], msg)
    return return_code

def gpg_main(word, word_eol, userdata):
    channel = hexchat.get_info("channel")
    
    if channel in recipients and not channel in gpg_off_channels:
        print_msg("Currently the messages you send on the channel {} are encrypted with these public keys:\n".format(channel), end=False)

        for recipient in recipients[channel]:
            print_msg("{}".format(recipient), begin=False, end=False)
    else:
        print_msg(begin=True, end=False)
        print_msg("Currently the messages you send on the channel {} are not encrypted.".format(channel), begin=False, end=False, color=RED)

    print_msg("\nTo list all available keys type: /list_keys\nTo add a key type: /add_key <key>\n(You can add multiple keys separated by comma)\nTo delete a key type: /del_key <key>", begin=False)

    return hexchat.EAT_ALL

def list_keys(word, word_eol, userdata):
    cmd = "{} --list-public-keys --with-colons".format(GPG_PATH)
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    out, err = p.communicate()
    if err:
        hexchat.prnt(err.decode('utf-8'))
        return hexchat.EAT_ALL

    print_msg("All public keys installed on your computer:", end=False)

    for line in out.decode('utf-8').split("\n"):
        if line.startswith("uid"):
            cols = line.split("::")
            print_msg(cols[4], begin=False, end=False)
    
    print_msg(begin=False, end=True)
    return hexchat.EAT_ALL

def add_key(word, word_eol, userdata):
    global recipients

    if not len(word_eol)>1:
        print_msg("You have to specify a key to add as argument", end=False, color=RED)
        print_msg("If yo want to list all availible keys type: /list_keys", begin=False) 
        return hexchat.EAT_ALL

    for key in word_eol[1].split(","):
        key = key.strip()
        channel = hexchat.get_info("channel")
        if not channel in recipients:
            recipients[channel] = []
        recipients[channel].append(key)
        print_msg("Added key {} to the recipient rules of channel {}".format(key, channel))

    return hexchat.EAT_ALL

def del_key(word, word_eol, userdata):
    global recipients

    if not len(word_eol)>1:
        print_msg("You have to specify a key to delete as argument\n", color=RED, end=False)
        print_msg("If yo want see the current recipient rule type: /gpg", begin=False)
        return hexchat.EAT_ALL

    for key in word_eol[1].split(","):
        key = key.strip()
        channel = hexchat.get_info("channel")
        if not recipients[channel]:
            print_msg("Currently there are no keys in the recipient rules for channel {}".format(channel), color=RED)
            return hexchat.EAT_ALL

        if not key in recipients[channel]:
            print_msg("Could not find key {} to be deleted.".format(key), color=RED)
            return hexchat.EAT_ALL
        
        while key in recipients[channel]:
            recipients[channel].remove(key)

        print_msg("Deleted key {}".format(key))

    return hexchat.EAT_ALL

def gpg_off(word, word_eol, userdata):
    global gpg_off_channels
    channel = hexchat.get_info("channel")
    print_msg("turning off automatic encryption on channel {}".format(channel), color=RED)
    gpg_off_channels.append(channel)
    return hexchat.EAT_ALL

def gpg_on(word, word_eol, userdata):
    global gpg_off_channels
    global recipients
    channel = hexchat.get_info("channel")
    print_msg("turning on automatic encryption on channel {}".format(channel))
    if channel in gpg_off_channels:
        gpg_off_channels.remove(channel)
    if not channel in recipients:
        recipients[channel] = []
    return hexchat.EAT_ALL

def store_settings(userdata):
    for setting in hexchat.list_pluginpref():
        if setting.startswith("gpg_#"):
            hexchat.del_pluginpref(setting)
    for channel in recipients:
        if recipients[channel] and not channel in gpg_off_channels:
            hexchat.set_pluginpref("gpg_{}".format(channel), ",".join(recipients[channel]))

def load_settings():
    global recipients
    global GPG_PATH
    for setting in hexchat.list_pluginpref():
        if setting.startswith("gpg_#"):
            channel = setting.lstrip("gpg_")
            recipients[channel] = []
            for recipient in hexchat.get_pluginpref(setting).split(","):
                recipients[channel].append(recipient)
    new_path = hexchat.get_pluginpref("gpg_path")
    if new_path:
        GPG_PATH = new_path

hexchat.hook_command("", command_hook, "say")
hexchat.hook_command("me", command_hook, "me")
hexchat.hook_print("Your Message", your_message_hook)
hexchat.hook_print("Channel Message", channel_msg_hook)
hexchat.hook_print("Your Action", your_action_hook)
hexchat.hook_print("Channel Action", channel_action_hook)
hexchat.hook_command("gpg", gpg_main)
hexchat.hook_command("list_keys", list_keys)
hexchat.hook_command("add_key", add_key)
hexchat.hook_command("del_key", del_key)
hexchat.hook_command("gpg_off", gpg_off)
hexchat.hook_command("gpg_on", gpg_on)
hexchat.hook_unload(store_settings)

load_settings()
