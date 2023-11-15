#!/bin/bash

#################################################
#   __       __  __    __   ______   __    __   #
#  |  \     /  \|  \  |  \ /      \ |  \  |  \  # 
#  | $$\   /  $$| $$  | $$|  $$$$$$\| $$  | $$| #
#  | $$$\ /  $$$| $$  | $$| $$___\$$| $$__| $$| # 
#  | $$$$\  $$$$| $$  | $$ \$$    \ | $$    $$| #  
#  | $$\$$ $$ $$| $$  | $$ _\$$$$$$\| $$$$$$$$| #  
#  | $$ \$$$| $$| $$__/ $$|  \__| $$| $$  | $$| #
#  | $$  \$ | $$ \$$    $$ \$$    $$| $$  | $$| #  
#   \$$      \$$  \$$$$$$   \$$$$$$  \$$   \$$| #  
#################################################
#
# Mush v1.0 - Release
# Mush v1.1 - Currently in progress, patching bugs, making ui more readable, and adding more utils
#
# Mush - the replacement for crosh whenever fakemurk is installed. It allows you
# to do anything to the OS basically. Instead of this being the normal mush that is installed
# with fakemurk, this is a modded version that comes with more colorful text, utils, etc.
#
# Created by misterfonka <misterfonka@gmail.com>
# Project link: https://github.com/misterfonka/MushMod
#
# May be freely distributed and modified as needed
# as long as lines 22 and 23 are kept in.

#########################
# REGULAR USE FUNCTIONS #
#########################

HWID=$(crossystem hwid | sed 's/X86//g' | sed 's/ *$//g' | sed 's/ /_/g')
BOARD=$(crossystem hwid | sed 's/X86//g' | sed 's/ *$//g'| awk 'NR==1{print $1}' | cut -f 1 -d'-')
FWVERSION=$(crossystem fwid)

# functions for colored text
echo_red() {
	echo -e "\E[0;31m$1\e[0m"
}

echo_green() {
	echo -e "\E[0;32m$1\e[0m"
}

echo_yellow() {
	echo -e "\E[1;33m$1\e[0m"
}

echo_blue() {
    echo -e "\033[34m$1\033[0m"
}

redread_text() {
  local text="$1"
  echo -ne "\e[31m$text\e[0m"
}

red_read() {
  local prompt="$1"
  local var_name="$2"
  
  redread_text "$prompt"
  read -r "$var_name"
}

# gets the largest NVMe namespace, most of the time your internal storage
get_largest_nvme_namespace() {
    # this function doesn't exist if the version is old enough, so we redefine it
    local largest size tmp_size dev
    size=0
    dev=$(basename "$1")

    for nvme in /sys/block/"${dev%n*}"*; do
        tmp_size=$(cat "${nvme}"/size)
        if [ "${tmp_size}" -gt "${size}" ]; then
            largest="${nvme##*/}"
            size="${tmp_size}"
        fi
    done
    echo "${largest}"
}

# find bugs
traps() {
    set +e
    trap 'last_command=$current_command; current_command=$BASH_COMMAND' DEBUG
    trap 'echo "\"${last_command}\" command failed with exit code $?. THIS IS A BUG, REPORT IT HERE https://github.com/MercuryWorkshop/fakemurk"' EXIT
    trap '' INT
}


# executes a command as root over SSH
doas() {
    # since the OS thinks we’re in verified mode, it refuses to let filesystems be mounted
    # with the “setuid” bit, breaking sudo in the proccess. so we have to use a SSH connection
    # to be able to run things as sudo/root.

    # if you wanna run a command as root, use 'ssh -t -p 1337 root@127.0.0.1'

    # another issue with the OS thinking we're in verified mode, since frecon doesn't run
    # in verified mode, you also can't access vt2/dev console.
    ssh -t -p 1337 -i /rootkey -oStrictHostKeyChecking=no root@127.0.0.1 "$@"
}

# executes a command in a subshell and sets up signal trapping
runjob() {
    trap 'kill -2 $! >/dev/null 2>&1' INT
    (
        $@
    )
    trap '' INT
}

# reads and discards input from stdin
swallow_stdin() {
    while read -t 0 notused; do
        read input
    done
}

# opens a file for editing
edit() {
    if which nano 2>/dev/null; then
        doas nano "$@"
    else
        doas vi "$@"
    fi
}

# https://chromium.googlesource.com/chromiumos/docs/+/master/lsb-release.md
# a utility function that extracts a value from an LSB (Linux Standard Base) release file
lsbval() {
  local key="$1"
  local lsbfile="${2:-/etc/lsb-release}"

  if ! echo "${key}" | grep -Eq '^[a-zA-Z0-9_]+$'; then
    return 1
  fi

  sed -E -n -e \
    "/^[[:space:]]*${key}[[:space:]]*=/{
      s:^[^=]+=[[:space:]]*::
      s:[[:space:]]+$::
      p
    }" "${lsbfile}"
}
# retrieves the booted kernal number
get_booted_kernnum() {
    if doas "((\$(cgpt show -n \"$dst\" -i 2 -P) > \$(cgpt show -n \"$dst\" -i 4 -P)))"; then
        echo -n 2
    else
        echo -n 4
    fi
}
# returns the opposite number of a given input (2 becomes 4, 4 becomes 2, etc.)
opposite_num() {
    if [ "$1" == "2" ]; then
        echo -n 4
    elif [ "$1" == "4" ]; then
        echo -n 2
    elif [ "$1" == "3" ]; then
        echo -n 5
    elif [ "$1" == "5" ]; then
        echo -n 3
    else
        return 1
    fi
}

##############################
# FUNCTIONS FOR ACTIONS CHOSE #
###############################

# everything below here is self explaintory so i wont be commenting stuff out
attempt_update(){
    local builds=$(curl https://chromiumdash.appspot.com/cros/fetch_serving_builds?deviceCategory=Chrome%20OS)
    local release_board=$(lsbval CHROMEOS_RELEASE_BOARD)
    local board=${release_board%%-*}
    local hwid=$(jq "(.builds.$board[] | keys)[0]" <<<"$builds")
    local hwid=${hwid:1:-1}
    local latest_milestone=$(jq "(.builds.$board[].$hwid.pushRecoveries | keys) | .[length - 1]" <<<"$builds")
    local remote_version=$(jq ".builds.$board[].$hwid[$latest_milestone].version" <<<"$builds")
    local remote_version=${remote_version:1:-1}
    local local_version=$(lsbval GOOGLE_RELEASE)

    if (( ${remote_version%%\.*} > ${local_version%%\.*} )); then
        echo "updating to ${remote_version}. THIS WILL DELETE YOUR REVERT BACKUP AND YOU WILL NO LONGER BE ABLE TO REVERT! THIS MAY ALSO DELETE ALL USER DATA!! press enter to confirm, ctrl-c to cancel"
        read -r
        sleep 4
        # read choice
        local reco_dl=$(jq ".builds.$board[].$hwid.pushRecoveries[$latest_milestone]" <<< "$builds")
        local tmpdir=/mnt/stateful_partition/update_tmp/
        doas mkdir $tmpdir
        echo "downloading ${remote_version} from ${reco_dl}"
        curl "${reco_dl:1:-1}" | doas "dd of=$tmpdir/image.zip status=progress"
        echo "unzipping update binary"
        cat $tmpdir/image.zip | gunzip | doas "dd of=$tmpdir/image.bin status=progress"
        doas rm -f $tmpdir/image.zip
        echo "invoking image patcher"
        doas image_patcher.sh "$tmpdir/image.bin"

        local loop=$(doas losetup -f | tr -d '\r')
        doas losetup -P "$loop" "$tmpdir/image.bin"
        echo "performing update"
        local dst=/dev/$(get_largest_nvme_namespace)
        local tgt_kern=$(opposite_num $(get_booted_kernnum))
        local tgt_root=$(( $tgt_kern + 1 ))

        local kerndev=${dst}p${tgt_kern}
        local rootdev=${dst}p${tgt_root}
        echo "installing kernel patch to ${kerndev}"
        doas dd if="${loop}p4" of="$kerndev" status=progress
        echo "installing root patch to ${rootdev}"
        doas dd if="${loop}p3" of="$rootdev" status=progress
        echo "setting kernel priority"
        doas cgpt add "$dst" -i 4 -P 0
        doas cgpt add "$dst" -i 2 -P 0
        doas cgpt add "$dst" -i "$tgt_kern" -P 1

        doas crossystem.old block_devmode=0
        doas vpd -i RW_VPD -s block_devmode=0

        # doas rm -rf $tmpdir
    
    else
        echo "update not required"
    fi
}

powerwash() {
    echo "ARE YOU SURE YOU WANT TO POWERWASH??? THIS WILL REMOVE ALL USER ACCOUNTS"
    sleep 2
    echo "(press enter to continue, ctrl-c to cancel)"
    swallow_stdin
    read -r
    # there is just a executable for powerwashing so i guess that is the easy way
    doas echo "fast safe" >/mnt/stateful_partition/factory_install_reset
    doas reboot
    exit
}

revert() {
    echo "This option will re-enroll your chromebook restore to before fakemurk was run. This is useful if you need to quickly go back to normal"
    echo "THIS IS A PERMANENT CHANGE!! YOU WILL NOT BE ABLE TO GO BACK UNLESS YOU UNENROLL AGAIN AND RUN THE SCRIPT, AND IF YOU UPDATE TO THE VERSION SH1MMER IS PATCHED, YOU MAY BE STUCK ENROLLED"
    echo "ARE YOU SURE YOU WANT TO CONTINUE? (press enter to continue, ctrl-c to cancel)"
    swallow_stdin
    read -r
    sleep 4
    echo "setting kernel priority"

    DST=/dev/$(get_largest_nvme_namespace)

    if doas "((\$(cgpt show -n \"$DST\" -i 2 -P) > \$(cgpt show -n \"$DST\" -i 4 -P)))"; then
        doas cgpt add "$DST" -i 2 -P 0
        doas cgpt add "$DST" -i 4 -P 1
    else
        doas cgpt add "$DST" -i 4 -P 0
        doas cgpt add "$DST" -i 2 -P 1
    fi
    echo "setting vpd"
    doas vpd -i RW_VPD -s check_enrollment=1
    doas vpd -i RW_VPD -s block_devmode=1
    doas crossystem.old block_devmode=1
    
    rm -f /stateful_unfucked

    echo "Done. Press enter to reboot"
    swallow_stdin
    read -r
    echo "bye!"
    sleep 2
    doas reboot
    sleep 1000
}

harddisableext() { # calling it "hard disable" because it only reenables when you press
    echo "Please choose the extension you wish to disable."
    echo "(1) GoGuardian"
    echo "(2) Securly Filter"
    echo "(3) LightSpeed Filter"
    echo "(4) Cisco Umbrella"
    echo "(5) ContentKeeper Authenticator"
    echo "(6) Hapara"
    echo "(7) iboss"
    echo "(8) LightSpeed Classroom"
    echo "(9) Blocksi"
    echo "(10) Linewize"
    echo "(11) Securly Classroom"
    echo "(12) Impero"
    echo "(13) put extension ID in manually"
    read -r -p "> (1-13): " choice
    case "$choice" in
    1) extid=haldlgldplgnggkjaafhelgiaglafanh;;
    2) extid=iheobagjkfklnlikgihanlhcddjoihkg;;
    3) extid=adkcpkpghahmbopkjchobieckeoaoeem;;
    4) extid=jcdhmojfecjfmbdpchihbeilohgnbdci;;
    5) extid=jdogphakondfdmcanpapfahkdomaicfa;;
    6) extid=aceopacgaepdcelohobicpffbbejnfac;;
    7) extid=kmffehbidlalibfeklaefnckpidbodff;;
    8) extid=jaoebcikabjppaclpgbodmmnfjihdngk;;
    9) extid=ghlpmldmjjhmdgmneoaibbegkjjbonbk;;
    10) extid=ddfbkhpmcdbciejenfcolaaiebnjcbfc;;
    11) extid=jfbecfmiegcjddenjhlbhlikcbfmnafd;;
    12) extid=jjpmjccpemllnmgiaojaocgnakpmfgjg;;
    13) read -r -p "enter extension id>" extid;;
    *) echo "invalid option" ;;
    esac
    echo "$extid" | grep -qE '^[a-z]{32}$' && chmod 000 "/home/chronos/user/Extensions/$extid" && kill -9 $(pgrep -f "\-\-extension\-process") || "invalid input"
}

hardenableext() {
    echo "Please choose the extension you wish to enable."
    echo "(1) GoGuardian"
    echo "(2) Securly Filter"
    echo "(3) LightSpeed Filter"
    echo "(4) Cisco Umbrella"
    echo "(5) ContentKeeper Authenticator"
    echo "(6) Hapara"
    echo "(7) iboss"
    echo "(8) LightSpeed Classroom"
    echo "(9) Blocksi"
    echo "(10) Linewize"
    echo "(11) Securly Classroom"
    echo "(12) Impero"
    echo "(13) put extension ID in manually"
    read -r -p "> (1-13): " choice
    case "$choice" in
    1) extid=haldlgldplgnggkjaafhelgiaglafanh;;
    2) extid=iheobagjkfklnlikgihanlhcddjoihkg;;
    3) extid=adkcpkpghahmbopkjchobieckeoaoeem;;
    4) extid=jcdhmojfecjfmbdpchihbeilohgnbdci;;
    5) extid=jdogphakondfdmcanpapfahkdomaicfa;;
    6) extid=aceopacgaepdcelohobicpffbbejnfac;;
    7) extid=kmffehbidlalibfeklaefnckpidbodff;;
    8) extid=jaoebcikabjppaclpgbodmmnfjihdngk;;
    9) extid=ghlpmldmjjhmdgmneoaibbegkjjbonbk;;
    10) extid=ddfbkhpmcdbciejenfcolaaiebnjcbfc;;
    11) extid=jfbecfmiegcjddenjhlbhlikcbfmnafd;;
    12) extid=jjpmjccpemllnmgiaojaocgnakpmfgjg;;
    13) read -r -p "enter extension id>" extid;;
    *) echo "invalid option" ;;
    esac
    echo "$extid" | grep -qE '^[a-z]{32}$' && chmod 777 "/home/chronos/user/Extensions/$extid" && kill -9 $(pgrep -f "\-\-extension\-process") || "invalid input"
}

softdisableext() {
    echo "Extensions will stay disabled until you press Ctrl+c or close this tab"
    while true; do
        kill -9 $(pgrep -f "\-\-extension\-process") 2>/dev/null
        sleep 0.5
    done
}

install_crouton() {
    doas "bash <(curl -SLk https://goo.gl/fd3zc) -t xfce -r bullseye"
    touch /mnt/stateful_partition/crouton
}

start_crouton() {
    doas "startxfce4"
}

credits() {
    clear
    echo "$(echo_red "[misterfonka]") $(echo_yellow "     - Creating MushMod")"
    echo "$(echo_red "[MercuryWorkshop]") $(echo_yellow " - Creating fakemurk, which made all of this possible")"
    red_read "Press enter to continue." ripge
}

revert_mush() {
    clear
    echo_red "Are you sure you want to do this? This can be reversible, but you will have to reinstall MushMod if wanted."
    read -p "Enter to confirm, CTRL+C to cancel."
    echo "Reverting MushMod back to mush..."
    doas "rm -f /usr/bin/crosh"
    doas "cp /usr/bin/mush.old /usr/bin/crosh"
    echo "Reverting complete! Reboot if needed."
    sleep 4
}

revert_crosh() {
    clear
    echo_red "ARE YOU SURE YOU WANT TO DO THIS!!!"
    echo ""
    echo_red "This is a bad idea, you will not be able to reinstall the mush shell after doing this."
    read -p "Press enter to confirm, CTRL+C to cancel."
    echo ""
    echo "Reverting mush back to crosh..."
    doas "rm -f /usr/bin/crosh"
    doas "cp /usr/bin/crosh.old /usr/bin/crosh"
    echo "Reverted successfully! Reboot if needed."
    sleep 4
}

fredestroyer() {
    clear
	echo_red "ARE YOU SURE YOU WANT TO DO THIS?"
	echo "THIS WILL BREAK FORCE RE-ENROLLMENT"
	echo "MEANING YOU CAN NEVER RE-ENROLL EVER AGAIN."
	echo "BY TYPING DoIt, YOU ACKNOWLEDGE THAT THE CREATOR"
	echo "IS NOT RESPONSIBLE FOR ANY DAMAGE/HARM THAT COMES"
	echo "FROM THIS SCRIPT."
	read -p "Type DoIt to accept and continue: " doit

	if [[ "$doit" = "DoIt" ]]; then
		echo ""
		echo_red "Breaking force re-enrollment..."
		doas "vpd -i "RW_VPD" -s "check_enrollment"="0" &> /dev/null"
  		doas "vpd -i "RW_VPD" -s "block_devmode"="0" &> /dev/null"
  		doas "vpd -d "stable_device_secret_DO_NOT_SHARE" &> /dev/null"
  		doas "dump_vpd_log --force &> /dev/null"
  		doas "crossystem clear_tpm_owner_request=1"
		echo ""
		echo "Done!"
		sleep 3
		clear
		echo "Rebooting. Please wait."
		sleep 5
		reboot
	else
		echo "Exiting..."
		exit 0
	fi
}

ResetGBB () {
    doas "/usr/share/vboot/bin/set_gbb_flags.sh 0  &> /dev/null"
}

ViewGBB () {
  doas "flashrom -r bios.bin &> /dev/null"
  doas "gbb_utility --get --flags bios.bin | grep -w "flags:" | tr -d "flags :""
  doas "rm bios.bin"
}

SetGBB() {
  doas "flashrom -r bios.bin &> /dev/null"
  doas "gbb_utility --set --flags=$set_gbbchoice bios.bin &> /dev/null"
  doas "flashrom -i GBB -w bios.bin &> /dev/null"
  doas "rm bios.bin"
}

gbbutils() {
    clear
    echo "Welcome to GBBUtils."
    echo "Note: Hardware WP needs to be off for everything except option 4."
    echo ""
    echo "1) Reset GBB Flags"
    echo "2) View Current GBB Flags"
    echo "3) Set GBB Flags"
    read -p "Enter the corresponding number for what you want to do: " gbbchoice

    if [[ "$gbbchoice" = "1" ]]; then
        clear
        echo "Are you sure you want to reset your GBB flags?"
        read -p "Type DoIt to confirm: " doit

        if [[ "$doit" = "DoIt" ]]; then
            clear
            echo "Setting GBB flags to factory default..."
            ResetGBB
            echo "Reset GBB flags successfully."
        else
            clear
            echo "User didn't want to do it..."
        fi

    elif [[ "$gbbchoice" = "2" ]]; then
        clear
        ViewGBB

    elif [[ "$gbbchoice" = "3" ]]; then
        clear
        read -p "What do you want to set the GBB flags to? " set_gbbchoice
        clear
        echo "Are you sure you want to set your GBB flags to $set_gbbchoice?"
        read -p "Type DoIt to confirm: " doit

        if [[ "$doit" = "DoIt" ]]; then
            clear
            echo "Setting GBB flags to $set_gbbchoice..."
            SetGBB
            echo "Set GBB flags to $set_gbbchoice successfully."
        else
            clear
            echo "User didn't want to do it..."
        fi
else
    echo "ERROR: INVALID CHOICE"
    exit 1
fi
}

show_crossystem_values() {
    clear
    echo_red "crossystem values:"
    crossystem
    echo_blue "--------------------------------------"
}

show_rw_vpd_values() {
    echo_red "RW_VPD values:"
    doas "vpd -i RW_VPD -l"
    echo_blue "--------------------------------------"
}

show_ro_vpd_values() {
    echo_red "RO_VPD values:"
    doas "vpd -i RO_VPD -l"
    echo_blue "--------------------------------------"
}

FWWPStatus() {
    fwwp_status=$(crossystem wpsw_cur)
    if [[ $fwwp_status == "0" ]]; then
        echo "Disabled"
    else
        echo "Enabled"
    fi
}

install_chromebrew() {
    doas 'su chronos -s /bin/bash -c "curl -Lsk git.io/vddgY | bash" && exit'
}

dumpbios() {
    clear
    echo "Are you sure you want to dump the current system BIOS/Firmware?"
    echo "Nothing bad can come from this, it will just make the bios.bin file"
    echo "in the directory you ran this script in."
    echo ""
    read -p "Type DoIt to confirm: " doit

    if [[ "$doit" = "DoIt" ]]; then
        clear
        echo "Dumping system BIOS/Firmware..."
        doas "pushd /home/chronos/user/Downloads
        clear
        flashrom -r bios.bin &> /dev/null
        popd
        exit"
        clear
        echo "Done! Look in /home/chronos/user/Downloads (just labeled 'Downloads' in the file explorer) for the .bin file."
        sleep 1
        echo "Dumped successfully."
    else
        clear
        echo "User didn't want to do it..."
    fi
}

firmwareutil() {
	clear
	curl -LOk mrchromebox.tech/firmware-util.sh
	clear
	doas "bash firmware-util.sh"
}

###################################
# DISPLAY MENU, OPTIONS, AND INFO #
###################################

# shows mushmod info
mushmod() {
    clear
    echo_green "Welcome to the MushMod Tools/Settings!"
    echo ""
    echo_blue "Choose a action:"
    echo ""
    echo "$(echo_red "[1]") $(echo_yellow " Revert to mush")"
    echo "$(echo_red "[2]") $(echo_yellow " Revert to crosh")"
    red_read "> [1-2]: " modchoice
    
        if [[ "$modchoice" = "1" ]]; then
            revert_mush
        elif [[ "$modchoice" = "2" ]]; then
            revert_crosh
        else 
            echo "ERROR: INVALID OPTION"
        fi
}

# Shows the mush info
mush_info() {
echo_green "Welcome to mush, the fakemurk developer shell."

echo_green "If you got here by mistake, don't panic! Just close this tab and carry on."

echo_green "This shell contains a list of utilities for performing certain actions on a fakemurked chromebook"

echo ""

echo_green "WP Status: $fwwp_status HWID: $HWID FW Version: $FWVERSION Boardname: $BOARD"

echo_red   "This installation of fakemurk has been modified by MushMod. Don't report any bugs you encounter to Mercury Workshop."

echo ""

echo_blue "Welcome to Mush! Here are some"
echo_blue "utilities you can use to enhance your"
echo_blue "fakemurk experience."
echo ""
}

# Main menu for mush
main() {
    traps
    mush_info
    while true; do
echo "$(echo_red "[1]") $(echo_yellow " MushMod Tools/Settings")"
echo "$(echo_red "[2]") $(echo_yellow " Root Shell")"
echo "$(echo_red "[3]") $(echo_yellow " Chronos Shell")"
echo "$(echo_red "[4]") $(echo_yellow " Crosh")"
echo "$(echo_red "[5]") $(echo_yellow " Powerwash")"
echo "$(echo_red "[6]") $(echo_yellow " Soft Disable Extensions")"
echo "$(echo_red "[7]") $(echo_yellow " Hard Disable Extensions")"
echo "$(echo_red "[8]") $(echo_yellow " Hard Enable Extensions")"
echo "$(echo_red "[9]") $(echo_yellow " Emergency Revert & Re-Enroll")"
echo "$(echo_red "[10]") $(echo_yellow "Edit Pollen")"

        if ! test -d /mnt/stateful_partition/crouton; then
            echo "$(echo_red "[11]") $(echo_yellow "Install Crouton")"
        else
            echo "$(echo_red "[12]") $(echo_yellow "Start Crouton")"
        fi

echo "$(echo_red "[13]") $(echo_yellow "FREDestroyer")"
echo "$(echo_red "[14]") $(echo_yellow "GBBUtils")"
echo "$(echo_red "[15]") $(echo_yellow "View configuration")"
echo "$(echo_red "[16]") $(echo_yellow "Dump BIOS/Firmware")"
echo "$(echo_red "[17]") $(echo_yellow "MrChromeboxes Firmware Utility")"
echo "$(echo_red "[18]") $(echo_yellow "[MAY BREAK] Update ChromeOS")"
echo "$(echo_red "[19]") $(echo_yellow "[MAY BREAK] Install Chromebrew")"
echo "$(echo_red "[C]") $(echo_yellow " MushMod About/Credits")"
echo "$(echo_red "[R]") $(echo_yellow " Reboot")"

        # users choice
        swallow_stdin
        red_read "> [1-12]: " choice

        if [[ "$choice" = "1" ]]; then
            mushmod

        elif [[ "$choice" = "2" ]]; then
            doas bash

        elif [[ "$choice" = "3" ]]; then
            bash

        elif [[ "$choice" = "4" ]]; then
            /usr/bin/crosh.old

        elif [[ "$choice" = "5" ]]; then
            powerwash

        elif [[ "$choice" = "6" ]]; then
            softdisableext

        elif [[ "$choice" = "7" ]]; then
            harddisableext

        elif [[ "$choice" = "8" ]]; then
            hardenableext

        elif [[ "$choice" = "9" ]]; then
            revert

        elif [[ "$choice" = "10" ]]; then
            edit /etc/opt/chrome/policies/managed/policy.json

        elif [[ "$choice" = "11" ]]; then
            install_crouton

        elif [[ "$choice" = "12" ]]; then
            start_crouton

        elif [[ "$choice" = "13" ]]; then
            fredestroyer

        elif [[ "$choice" = "14" ]]; then
            gbbutils

        elif [[ "$choice" = "15" ]]; then 
            show_crossystem_values
	        show_rw_vpd_values
	        show_ro_vpd_values

        elif [[ "$choice" = "16" ]]; then 
            dumpbios

        elif [[ "$choice" = "17" ]]; then 
            firmwareutil

        elif [[ "$choice" = "18" ]]; then 
            attempt_update

        elif [[ "$choice" = "19" ]]; then 
            install_chromebrew

        elif [[ "$choice" =~ [Rr] ]]; then
	        reboot

        elif [[ "$choice" =~ [Cc] ]]; then
	        credits

        else
            echo "ERROR: Invalid option."
        fi
    done
}

if [ "$0" = "$BASH_SOURCE" ]; then
    stty sane
    main
fi
