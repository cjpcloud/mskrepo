 #! /bin/bash
        # Guide to the Secure Configuration of Ubuntu 22.04
        # Install AIDE

        DEBIAN_FRONTEND=noninteractive apt-get install -y "aide"
        # Build and Test AIDE Database
        #aideinit
        sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

        if grep -i '^.*/usr/sbin/auditctl.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/auditctl.*#/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        if grep -i '^.*/usr/sbin/auditd.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/auditd.*#/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        if grep -i '^.*/usr/sbin/ausearch.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/ausearch.*#/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        if grep -i '^.*/usr/sbin/aureport.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/aureport.*#/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        if grep -i '^.*/usr/sbin/autrace.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/autrace.*#/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        if grep -i '^.*/usr/sbin/augenrules.*$' /etc/aide/aide.conf; then
        sed -i "s#.*/usr/sbin/augenrules.*#/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512#" /etc/aide/aide.conf
        else
        echo "/usr/sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512" >> /etc/aide/aide.conf
        fi

        # Configure AIDE to Verify the Audit Tools

        AIDE_CONFIG=/etc/aide/aide.conf
        DEFAULT_DB_PATH=/var/lib/aide/aide.db

        # Fix db path in the config file, if necessary
        if ! grep -q '^database=file:' ${AIDE_CONFIG}; then
            # replace_or_append gets confused by 'database=file' as a key, so should not be used.
            #replace_or_append "${AIDE_CONFIG}" '^database=file' "${DEFAULT_DB_PATH}" '@CCENUM@' '%s:%s'
            echo "database=file:${DEFAULT_DB_PATH}" >> ${AIDE_CONFIG}
        fi

        # Fix db out path in the config file, if necessary
        if ! grep -q '^database_out=file:' ${AIDE_CONFIG}; then
            echo "database_out=file:${DEFAULT_DB_PATH}.new" >> ${AIDE_CONFIG}
        fi

        #/usr/sbin/aideinit -y -f

        # Configure Periodic Execution of AIDE

        echo "05 4 * * 0 root /usr/bin/aide --config /etc/aide/aide.conf --check" >> /etc/crontab

        # Package "prelink" Must not be Installed
        apt-get remove prelink -y

        # Ensure shadow group is empty
        grep '^root:[!*]:' /etc/shadow


        # Install sudo Package
        apt-get update
        apt install sudo -y

        # Ensure Only Users Logged In To Real tty Can Execute Sudo - sudo use_pty

        readarray -t users_with_empty_pass < <(sudo awk -F: '!$2 {print $1}' /etc/shadow)

        passwd -l $user_with_empty_pass


        # Ensure Sudo Logfile Exists - sudo logfile

        echo "Defaults logfile=/var/log/sudo.log " >> /etc/sudoers

        # Require Re-Authentication When Using the sudo Command

        sed -i "s/timestamp_timeout=5/timestamp_timeout=15/g" /etc/sudoers >> /etc/sudoers

        if grep -q 'timestamp_timeout=15' /etc/sudoers
        then
            # exit status of grep is zero: the pattern DOES MATCH the file
            echo "line is in the file";
        else
            # exit status of grep is non-zero: the pattern DOES NOT MATCH the file
            echo "line is not present";
            echo "Defaults timestamp_timeout=15" >> /etc/sudoers

        fi

        # Set Password Hashing Algorithm in /etc/login.defs

        sed -i "s/^ENCRYPT_METHOD .*/ENCRYPT_METHOD yescrypt/g" /etc/login.defs >> /etc/login.defs

        # Install pam_pwquality Package

        apt-get install libpam-pwquality -y

        # Ensure Authentication Required for Single User Mode

        sudo echo "root:123456789" | chpasswd

        # Ensure the Default Bash Umask is Set Correctly

        if grep -q '^umask' /etc/bash.bashrc
        then
            # exit status of grep is zero: the pattern DOES MATCH the file
            echo "line is in the file";
        else
            # exit status of grep is non-zero: the pattern DOES NOT MATCH the file
            echo "line is not present";
            echo "umask 027" >> /etc/bash.bashrc;

        fi

        if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

        var_accounts_user_umask='027'


        # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
        # Otherwise, regular sed command will do.
        sed_command=('sed' '-i')
        if test -L "/etc/login.defs"; then
            sed_command+=('--follow-symlinks')
        fi

        # Strip any search characters in the key arg so that the key can be replaced without
        # adding any search characters to the config file.
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^UMASK")

        # shellcheck disable=SC2059
        printf -v formatted_output "%s %s" "$stripped_key" "$var_accounts_user_umask"

        # If the key exists, change it. Otherwise, add it to the config_file.
        # We search for the key string followed by a word boundary (matched by \>),
        # so if we search for 'setting', 'setting2' won't match.
        if LC_ALL=C grep -q -m 1 -i -e "^UMASK\\>" "/etc/login.defs"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            "${sed_command[@]}" "s/^UMASK\\>.*/$escaped_formatted_output/gi" "/etc/login.defs"
        else
            if [[ -s "/etc/login.defs" ]] && [[ -n "$(tail -c 1 -- "/etc/login.defs" || true)" ]]; then
                LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/login.defs"
            fi

            printf '%s\n' "$formatted_output" >> "/etc/login.defs"
        fi

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi


        # Ensure the Default Umask is Set Correctly in /etc/profile

        if grep -q '^umask' /etc/profile
        then

            echo "line is in the file";
        else

            echo "line is not present";
            echo "umask 027" >> /etc/profile;

        fi

        # Ensure the Default Umask is Set Correctly in login.defs

        sed -i "s/^UMASK .*/UMASK 027/g" /etc/login.defs >> /etc/login.defs

        # Set Interactive Session Timeout

        if grep -q '^TMOUT' /etc/profile
        then
            # exit status of grep is zero: the pattern DOES MATCH the file
            echo "line is in the file";
        else
            # exit status of grep is non-zero: the pattern DOES NOT MATCH the file
            echo "line is not present";
            echo "TMOUT=900" >> /etc/profile;

        fi

        var_accounts_tmout='900'


        # if 0, no occurence of tmout found, if 1, occurence found
        tmout_found=0

        for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if grep --silent '^\s*TMOUT' $f; then
                sed -i -E "s/^(\s*)TMOUT\s*=\s*(\w|\$)*(.*)$/\1TMOUT=$var_accounts_tmout\3/g" $f
                tmout_found=1
                if ! grep --silent '^\s*readonly TMOUT' $f ; then
                    echo "readonly TMOUT" >> $f
                fi
                if ! grep --silent '^\s*export TMOUT' $f ; then
                    echo "export TMOUT" >> $f
                fi
            fi
        done

        if [ $tmout_found -eq 0 ]; then
                echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
                echo "TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
                echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
                echo "export TMOUT" >> /etc/profile.d/tmout.sh
        fi



        # Verify /boot/grub/grub.cfg Permissions

        sudo chmod 600 /boot/grub/grub.cfg

        # Install systemd-journal-remote Package

        apt-get install -y "systemd-journal-remote"

        # Ensure Logs Sent To Remote Host

        rsyslog_remote_loghost_address='logcollector'
        # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
        # Otherwise, regular sed command will do.
        sed_command=('sed' '-i')
        if test -L "/etc/rsyslog.conf"; then
            sed_command+=('--follow-symlinks')
        fi

        # Strip any search characters in the key arg so that the key can be replaced without
        # adding any search characters to the config file.
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^\*\.\*")

        # shellcheck disable=SC2059
        printf -v formatted_output "%s %s" "$stripped_key" "@@$rsyslog_remote_loghost_address"

        # If the key exists, change it. Otherwise, add it to the config_file.
        # We search for the key string followed by a word boundary (matched by \>),
        # so if we search for 'setting', 'setting2' won't match.
        if LC_ALL=C grep -q -m 1 -i -e "^\*\.\*\\>" "/etc/rsyslog.conf"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            "${sed_command[@]}" "s/^\*\.\*\\>.*/$escaped_formatted_output/gi" "/etc/rsyslog.conf"
        else
            if [[ -s "/etc/rsyslog.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/rsyslog.conf" || true)" ]]; then
                LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/rsyslog.conf"
            fi

            printf '%s\n' "$formatted_output" >> "/etc/rsyslog.conf"
        fi

        # Configure Accepting Router Advertisements on All IPv6 Interfaces
        sudo sysctl -w net.ipv6.conf.all.accept_ra=0
        echo "net.ipv6.conf.all.accept_ra = 0" >> /etc/sysctl.conf


        # Disable Accepting ICMP Redirects for All IPv6 Interfaces
        sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
        echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv6 Interfaces
         echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf


        # Disable Kernel Parameter for IPv6 Forwarding
        echo "net.ipv6.conf.all.forwarding = 0" >> /etc/sysctl.conf

        # Disable Accepting Router Advertisements on all IPv6 Interfaces by Default
        sudo sysctl -w net.ipv6.conf.default.accept_ra=0
        echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv6 Interfaces
        sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
        echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting Source-Routed Packets on IPv6 Interfaces by Default
        echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

        # Disable Accepting ICMP Redirects for All IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
        echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting Source-Routed Packets on all IPv4 Interfaces
        echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf

        # Enable Kernel Parameter to Log Martian Packets on all IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.all.log_martians=1
        echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf

        # Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.all.rp_filter=1
        echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        # Comment out any occurrences of net.ipv4.conf.all.rp_filter from /etc/sysctl.d/*.conf files

        for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do


          # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
          if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

          matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.all.rp_filter.*$' $f | uniq )
          if ! test -z "$matching_list"; then
            while IFS= read -r entry; do
              escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
              # comment out "net.ipv4.conf.all.rp_filter" matches to preserve user data
              sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
            done <<< "$matching_list"
          fi
        done
        sysctl_net_ipv4_conf_all_rp_filter_value='1'


        #
        # Set runtime for net.ipv4.conf.all.rp_filter
        #
        /sbin/sysctl -q -n -w net.ipv4.conf.all.rp_filter="$sysctl_net_ipv4_conf_all_rp_filter_value"

        #
        # If net.ipv4.conf.all.rp_filter present in /etc/sysctl.conf, change value to appropriate value
        #       else, add "net.ipv4.conf.all.rp_filter = value" to /etc/sysctl.conf
        #
        # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
        # Otherwise, regular sed command will do.
        sed_command=('sed' '-i')
        if test -L "/etc/sysctl.conf"; then
            sed_command+=('--follow-symlinks')
        fi

        # Strip any search characters in the key arg so that the key can be replaced without
        # adding any search characters to the config file.
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.all.rp_filter")

        # shellcheck disable=SC2059
        printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_all_rp_filter_value"

        # If the key exists, change it. Otherwise, add it to the config_file.
        # We search for the key string followed by a word boundary (matched by \>),
        # so if we search for 'setting', 'setting2' won't match.
        if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.all.rp_filter\\>" "/etc/sysctl.conf"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            "${sed_command[@]}" "s/^net.ipv4.conf.all.rp_filter\\>.*/$escaped_formatted_output/gi" "/etc/sysctl.conf"
        else
            if [[ -s "/etc/sysctl.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/sysctl.conf" || true)" ]]; then
                LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/sysctl.conf"
            fi

            printf '%s\n' "$formatted_output" >> "/etc/sysctl.conf"
        fi

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Disable Kernel Parameter for Accepting Secure ICMP Redirects on all IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
        echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting ICMP Redirects by Default on IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
        echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Accepting Source-Routed Packets on IPv4 Interfaces by Default
        echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf

        # Enable Kernel Paremeter to Log Martian Packets on all IPv4 Interfaces by Default
        sudo sysctl -w net.ipv4.conf.default.log_martians=1
        echo "net.ipv4.conf.default.log_martians = 1" >> /etc/sysctl.conf

        # Enable Kernel Parameter to Use Reverse Path Filtering on all IPv4 Interfaces by Default
        sudo sysctl -w net.ipv4.conf.default.rp_filter=1
        echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

        # Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

        for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do


          # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
          if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

          matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
          if ! test -z "$matching_list"; then
            while IFS= read -r entry; do
              escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
              # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
              sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
            done <<< "$matching_list"
          fi
        done
        sysctl_net_ipv4_conf_default_rp_filter_value='1'


        #
        # Set runtime for net.ipv4.conf.default.rp_filter
        #
        /sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"

        #
        # If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
        #       else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
        #
        # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
        # Otherwise, regular sed command will do.
        sed_command=('sed' '-i')
        if test -L "/etc/sysctl.conf"; then
            sed_command+=('--follow-symlinks')
        fi

        # Strip any search characters in the key arg so that the key can be replaced without
        # adding any search characters to the config file.
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")

        # shellcheck disable=SC2059
        printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"

        # If the key exists, change it. Otherwise, add it to the config_file.
        # We search for the key string followed by a word boundary (matched by \>),
        # so if we search for 'setting', 'setting2' won't match.
        if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "/etc/sysctl.conf"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            "${sed_command[@]}" "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "/etc/sysctl.conf"
        else
            if [[ -s "/etc/sysctl.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/sysctl.conf" || true)" ]]; then
                LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/sysctl.conf"
            fi

            printf '%s\n' "$formatted_output" >> "/etc/sysctl.conf"
        fi


        # Disable Kernel Parameter for IP Forwarding on IPv4 Interfaces

        echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

        # Disable Core Dumps for SUID programs

        sudo sysctl -w fs.suid_dumpable=0

        echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

        # Configure Kernel Parameter for Accepting Secure Redirects By Default
        echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
        sudo sysctl -w net.ipv4.conf.default.secure_redirects=0

        # Enable Kernel Parameter to Ignore ICMP Broadcast Echo Requests on IPv4 Interfaces
        echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf

        # Enable Kernel Parameter to Ignore Bogus ICMP Error Responses on IPv4 Interfaces
        echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf

        # Enable Kernel Parameter to Use TCP Syncookies on Network Interfaces
        echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces
        sudo sysctl -w net.ipv4.conf.all.send_redirects=0
        echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf

        # Disable Kernel Parameter for Sending ICMP Redirects on all IPv4 Interfaces by Default
        sudo sysctl -w net.ipv4.conf.default.send_redirects=0
        echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf

        # Remove ufw Package
        apt-get remove ufw -y
        systemctl enable ufw.service


        # Disable Postfix Network Listening
        sed -i "s/^inet_interfaces .*/inet_interfaces = loopback-only/g" /etc/postfix/main.cf >> /etc/postfix/main.cf
        systemctl restart postfix

        # Ensure No World-Writable Files Exist
        FILTER_NODEV=$(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,)
        PARTITIONS=$(findmnt -n -l -k -it $FILTER_NODEV | awk '{ print $1 }')
        for PARTITION in $PARTITIONS; do
          find "${PARTITION}" -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
        done

        # Ensure /tmp is also fixed whem tmpfs is used.
        if grep "^tmpfs /tmp" /proc/mounts; then
          find /tmp -xdev -type f -perm -002 -exec chmod o-w {} \; 2>/dev/null
        fi

        # Verify permissions of log files
        find -H /var/log/  -perm /u+xs,g+xws,o+xwrt ! -name 'history.log' ! -name 'eipp.log.xz' ! -name '*[bw]tmp' ! -name '*lastlog' -type f -regex '.*' -exec chmod u-xs,g-xws,o-xwrt {} \;

        # Disable Modprobe Loading of USB Storage Driver
        echo "install usb-storage /bin/false" >> /etc/modprobe.d/usb-storage.conf

        # Disable Core Dumps for All Users
        echo "*     hard   core    0" >> /etc/security/limits.conf

        # Disable Core Dumps for SUID programs
        echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

        # Enable Randomized Layout of Virtual Address Space
        echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

        # Disable Apport Service
        sudo systemctl mask --now apport.service

        # Verify Group Who Owns cron.daily
        sudo chmod 0700 /etc/cron.daily

        # Verify Group Who Owns cron.hourly
        sudo chgrp root /etc/cron.hourly

        # Verify Permissions on cron.hourly
        sudo chmod 0700 /etc/cron.hourly

        # Verify Group Who Owns cron.monthly
        sudo chmod 0700 /etc/cron.monthly

        # Verify Group Who Owns cron.weekly
        sudo chmod 0700 /etc/cron.weekly

        # Verify Group Who Owns Crontab
        sudo chmod 0600 /etc/crontab


        # Verify Owner on cron.d
        sudo chmod 0700 /etc/cron.d

        # Uninstall rsync Package
        apt-get remove rsync -y

        # Set SSH Client Alive Count Max
        if grep -q 'ClientAliveCountMax' /etc/ssh/sshd_config
        then

            echo "line is in the file";
        else

            echo "line is not present";
            echo "ClientAliveCountMax 3" >> /etc/ssh/sshd_config;

        fi
        printf '%s\n' "ClientAliveCountMax 3" >> "/etc/ssh/sshd_config"

        # Set SSH Client Alive Interval
        if grep -q 'ClientAliveInterval' /etc/ssh/sshd_config
        then

            echo "line is in the file";
        else

            echo "line is not present";
            echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config;

        fi

         echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config

        # Disable Host-Based Authentication
        printf '%s\n' "HostbasedAuthentication no" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

        # Disable SSH Access via Empty Passwords
        printf '%s\n' "PermitEmptyPasswords no" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

        # Disable SSH Support for .rhosts Files
        printf '%s\n' "IgnoreRhosts yes" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

        # Disable SSH Root Login
        printf '%s\n' "PermitRootLogin no" >> "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"

        # Do Not Allow SSH Environment Options
        printf '%s\n' "PermitUserEnvironment no" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

        # Enable SSH Warning Banner
        printf '%s\n' "Banner /etc/issue.net" >> "/etc/ssh/sshd_config.d/00-complianceascode-hardening.conf"

        # Ensure SSH LoginGraceTime is configured
        printf '%s\n' "LoginGraceTime 60" >> "/etc/ssh/sshd_config"

        # Set LogLevel to INFO
        printf '%s\n' "LogLevel INFO" >> "/etc/ssh/sshd_config.d/01-complianceascode-reinforce-os-defaults.conf"

        # Set SSH authentication attempt limit
        printf '%s\n' "MaxAuthTries 4" >> "/etc/ssh/sshd_config"

        # Set SSH MaxSessions limit
        printf '%s\n' "MaxSessions 10" >> "/etc/ssh/sshd_config"

        # Ensure SSH MaxStartups is configured
        printf '%s\n' "MaxStartups 10:30:60" >> "/etc/ssh/sshd_config"

        # Use Only Strong Ciphers
        printf '%s\n' "Ciphers aes128-ctr,aes192-ctr,aes256-ctr,chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com" >> "/etc/ssh/sshd_config"

        # Use Only Strong Key Exchange algorithms
        printf '%s\n' "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18 sha512,diffie-hellman-group14-sha256" >> "/etc/ssh/sshd_config"

        # Use Only Strong MACs
        printf '%s\n' "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> "/etc/ssh/sshd_config"

        # Remove iptables-persistent Package

        apt-get remove iptables-persistent

        # Remove telnet Clients

        apt-get remove -y "telnet"

        # Disable Mounting of cramfs

        echo "install cramfs /bin/false" >> /etc/modprobe.d/cramfs.conf

        # Ensure journald is configured to write log files to persistent disk
        printf '%s\n' "Storage='persistent'" >> "/etc/systemd/journald.conf"

        if [ -e "/etc/systemd/journald.conf" ] ; then

            LC_ALL=C sed -i "/^\s*Compress\s*=\s*/d" "/etc/systemd/journald.conf"
        else
            touch "/etc/systemd/journald.conf"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/systemd/journald.conf"

        cp "/etc/systemd/journald.conf" "/etc/systemd/journald.conf.bak"
        # Insert before the line matching the regex '^#\s*Compress'.
        line_number="$(LC_ALL=C grep -n "^#\s*Compress" "/etc/systemd/journald.conf.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '^#\s*Compress', insert at
            # the end of the file.
            printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
        else
            head -n "$(( line_number - 1 ))" "/etc/systemd/journald.conf.bak" > "/etc/systemd/journald.conf"
            printf '%s\n' "Compress='yes'" >> "/etc/systemd/journald.conf"
            tail -n "+$(( line_number ))" "/etc/systemd/journald.conf.bak" >> "/etc/systemd/journald.conf"
        fi
        # Clean up after ourselves.
        rm "/etc/systemd/journald.conf.bak"


        # Verify Permissions on SSH Server config file
        sudo chmod 0600 /etc/ssh/sshd_config


        # Use Only Strong Key Exchange algorithms

        sshd_strong_kex='ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256'


        if [ -e "/etc/ssh/sshd_config" ] ; then

            LC_ALL=C sed -i "/^\s*KexAlgorithms\s\+/Id" "/etc/ssh/sshd_config"
        else
            touch "/etc/ssh/sshd_config"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/ssh/sshd_config"

        cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
        # Insert before the line matching the regex '^Match'.
        line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '^Match', insert at
            # the end of the file.
            printf '%s\n' "KexAlgorithms $sshd_strong_kex" >> "/etc/ssh/sshd_config"
        else
            head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
            printf '%s\n' "KexAlgorithms $sshd_strong_kex" >> "/etc/ssh/sshd_config"
            tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
        fi
        # Clean up after ourselves.
        rm "/etc/ssh/sshd_config.bak"

        # file system permissions
        egrep -q  '/var/.+noexec' /etc/fstab || sed -ri '/\/var/ s/defaults/defaults,noexec/' /etc/fstab
        egrep -q  '/var/.+nodev' /etc/fstab || sed -ri '/\/var/ s/defaults/defaults,nodev/' /etc/fstab
        egrep -q  '/var/.+nosuid' /etc/fstab || sed -ri '/\/var/ s/defaults/defaults,nosuid/' /etc/fstab


        egrep -q  '/home/.+nodev' /etc/fstab || sed -ri '/\/home/ s/defaults/defaults,nodev/' /etc/fstab
        egrep -q  '/home/.+nosuid' /etc/fstab || sed -ri '/\/home/ s/defaults/defaults,nosuid/' /etc/fstab

        egrep -q  '/tmp/.+noexec' /etc/fstab || sed -ri '/\/tmp/ s/defaults/defaults,noexec/' /etc/fstab
        egrep -q  '/tmp/.+nodev' /etc/fstab || sed -ri '/\/tmp/ s/defaults/defaults,nodev/' /etc/fstab
        egrep -q  '/tmp/.+nosuid' /etc/fstab || sed -ri '/\/tmp/ s/defaults/defaults,nosuid/' /etc/fstab

        sudo sed -i '/\/var\/tmp/s/,*\(nosuid\|noexec\|nodev\)//g' /etc/fstab
        sed -i '/\/var\/tmp\s/ s/defaults/defaults,nodev,noexec,nosuid/' /etc/fstab



        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

        # Try find '[xdmcp]' and 'Enable' in '/etc/gdm3/custom.conf', if it exists, set
        # to 'false', if it isn't here, add it, if '[xdmcp]' doesn't exist, add it there
        if grep -qzosP '[[:space:]]*\[xdmcp]([^\n\[]*\n+)+?[[:space:]]*Enable' '/etc/gdm3/custom.conf'; then

            sed -i "s/Enable[^(\n)]*/Enable=false/" '/etc/gdm3/custom.conf'
        elif grep -qs '[[:space:]]*\[xdmcp]' '/etc/gdm3/custom.conf'; then
            sed -i "/[[:space:]]*\[xdmcp]/a Enable=false" '/etc/gdm3/custom.conf'
        else
            if test -d "/etc/gdm3"; then
                printf '%s\n' '[xdmcp]' "Enable=false" >> '/etc/gdm3/custom.conf'
            else
                echo "Config file directory '/etc/gdm3' doesnt exist, not remediating, assuming non-applicability." >&2
            fi
        fi

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
        DBDIR="/etc/dconf/db/gdm.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*disable-user-list\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)disable-user-list(\s*=)/#\1disable-user-list\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*disable-user-list\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*disable-user-list\\s*=\\s*.*/disable-user-list=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/login-screen\\]|a\\disable-user-list=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/login-screen/disable-user-list$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/login-screen/disable-user-list$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/login-screen/disable-user-list$" /etc/dconf/db/gdm.d/
        then
            echo "/org/gnome/login-screen/disable-user-list" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*automount\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)automount(\s*=)/#\1automount\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
        if grep -q "^\\s*automount\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*automount\\s*=\\s*.*/automount=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/local.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/desktop/media-handling/automount$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/desktop/media-handling/automount$" /etc/dconf/db/local.d/
        then
            echo "/org/gnome/desktop/media-handling/automount" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi


        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*automount-open\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)automount-open(\s*=)/#\1automount-open\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "false")"
        if grep -q "^\\s*automount-open\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*automount-open\\s*=\\s*.*/automount-open=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\automount-open=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/automount-open$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/local.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/desktop/media-handling/automount-open$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/desktop/media-handling/automount-open$" /etc/dconf/db/local.d/
        then
            echo "/org/gnome/desktop/media-handling/automount-open" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi


        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/media-handling\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*autorun-never\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)autorun-never(\s*=)/#\1autorun-never\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/media-handling\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/media-handling]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*autorun-never\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*autorun-never\\s*=\\s*.*/autorun-never=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/media-handling\\]|a\\autorun-never=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/desktop/media-handling/autorun-never$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/local.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/desktop/media-handling/autorun-never$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/desktop/media-handling/autorun-never$" /etc/dconf/db/local.d/
        then
            echo "/org/gnome/desktop/media-handling/autorun-never" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi


        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)


        var_screensaver_lock_delay='0'


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*lock-delay\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)lock-delay(\s*=)/#\1lock-delay\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "uint32 ${var_screensaver_lock_delay}")"
        if grep -q "^\\s*lock-delay\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*lock-delay\\s*=\\s*.*/lock-delay=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-delay=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)



        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*lock-enabled\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)lock-enabled(\s*=)/#\1lock-enabled\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*lock-enabled\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*lock-enabled\\s*=\\s*.*/lock-enabled=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-enabled=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/local.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
        then
            echo "/org/gnome/desktop/screensaver/lock-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)



        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/desktop/screensaver\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|local.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/local.d/00-security-settings"
        DBDIR="/etc/dconf/db/local.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*lock-enabled\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)lock-enabled(\s*=)/#\1lock-enabled\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/desktop/screensaver\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/desktop/screensaver]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*lock-enabled\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*lock-enabled\\s*=\\s*.*/lock-enabled=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/desktop/screensaver\\]|a\\lock-enabled=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/desktop/screensaver/lock-enabled$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|local.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/local.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/desktop/screensaver/lock-enabled$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/desktop/screensaver/lock-enabled$" /etc/dconf/db/local.d/
        then
            echo "/org/gnome/desktop/screensaver/lock-enabled" >> "/etc/dconf/db/local.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed && { [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; }; then

        # configure two dconf profiles:
        # - gdm: required for banner/user_list settings
        # - user: required for screenlock,automount,ctrlaltdel,... settings
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi# Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        # Duplicate the setting also in 'greeter.dconf-defaults' for consistency with
        # 'dconf_gnome_login_banner_text' and better alignment with STIG V1R1.
        if [ -e "/etc/gdm3/greeter.dconf-defaults" ] ; then

            LC_ALL=C sed -i "/^\s*banner\-message\-enable/Id" "/etc/gdm3/greeter.dconf-defaults"
        else
            touch "/etc/gdm3/greeter.dconf-defaults"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/gdm3/greeter.dconf-defaults"

        cp "/etc/gdm3/greeter.dconf-defaults" "/etc/gdm3/greeter.dconf-defaults.bak"
        # Insert after the line matching the regex '\[org/gnome/login-screen\]'
        line_number="$(LC_ALL=C grep -n "\[org/gnome/login-screen\]" "/etc/gdm3/greeter.dconf-defaults.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '\[org/gnome/login-screen\]', insert at
            # the end of the file.
            printf '%s\n' "banner-message-enable=true" >> "/etc/gdm3/greeter.dconf-defaults"
        else
            head -n "$(( line_number ))" "/etc/gdm3/greeter.dconf-defaults.bak" > "/etc/gdm3/greeter.dconf-defaults"
            printf '%s\n' "banner-message-enable=true" >> "/etc/gdm3/greeter.dconf-defaults"
            tail -n "+$(( line_number + 1 ))" "/etc/gdm3/greeter.dconf-defaults.bak" >> "/etc/gdm3/greeter.dconf-defaults"
        fi
        # Clean up after ourselves.
        rm "/etc/gdm3/greeter.dconf-defaults.bak"


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
        DBDIR="/etc/dconf/db/gdm.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*banner-message-enable\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)banner-message-enable(\s*=)/#\1banner-message-enable\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*banner-message-enable\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*banner-message-enable\\s*=\\s*.*/banner-message-enable=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-enable=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-enable$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/login-screen/banner-message-enable$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/login-screen/banner-message-enable$" /etc/dconf/db/gdm.d/
        then
            echo "/org/gnome/login-screen/banner-message-enable" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

        login_banner_text='^Authorized[\s\n]+uses[\s\n]+only\.[\s\n]+All[\s\n]+activity[\s\n]+may[\s\n]+be[\s\n]+monitored[\s\n]+and[\s\n]+reported\.$'


        # Multiple regexes transform the banner regex into a usable banner
        # 0 - Remove anchors around the banner text
        login_banner_text=$(echo "$login_banner_text" | sed 's/^\^\(.*\)\$$/\1/g')
        # 1 - Keep only the first banners if there are multiple
        #    (dod_banners contains the long and short banner)
        login_banner_text=$(echo "$login_banner_text" | sed 's/^(\(.*\.\)|.*)$/\1/g')
        # 2 - Add spaces ' '. (Transforms regex for "space or newline" into a " ")
        login_banner_text=$(echo "$login_banner_text" | sed 's/\[\\s\\n\]+/ /g')
        # 3 - Adds newline "tokens". (Transforms "(?:\[\\n\]+|(?:\\n)+)" into "(n)*")
        login_banner_text=$(echo "$login_banner_text" | sed 's/(?:\[\\n\]+|(?:\\\\n)+)/(n)*/g')
        # 4 - Remove any leftover backslash. (From any parethesis in the banner, for example).
        login_banner_text=$(echo "$login_banner_text" | sed 's/\\//g')
        # 5 - Removes the newline "token." (Transforms them into newline escape sequences "\n").
        #    ( Needs to be done after 4, otherwise the escapce sequence will become just "n".
        login_banner_text=$(echo "$login_banner_text" | sed 's/(n)\*/\\n/g')

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)

        # Will do both approach, since we plan to migrate to checks over dconf db. That way, future updates of the tool
        # will pass the check even if we decide to check only for the dconf db path.
        if [ -e "/etc/gdm3/greeter.dconf-defaults" ] ; then

            LC_ALL=C sed -i "/^\s*banner\-message\-text/Id" "/etc/gdm3/greeter.dconf-defaults"
        else
            touch "/etc/gdm3/greeter.dconf-defaults"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/gdm3/greeter.dconf-defaults"

        cp "/etc/gdm3/greeter.dconf-defaults" "/etc/gdm3/greeter.dconf-defaults.bak"
        # Insert after the line matching the regex '\[org/gnome/login-screen\]'
        line_number="$(LC_ALL=C grep -n "\[org/gnome/login-screen\]" "/etc/gdm3/greeter.dconf-defaults.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '\[org/gnome/login-screen\]', insert at
            # the end of the file.
            printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
        else
            head -n "$(( line_number ))" "/etc/gdm3/greeter.dconf-defaults.bak" > "/etc/gdm3/greeter.dconf-defaults"
            printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
            tail -n "+$(( line_number + 1 ))" "/etc/gdm3/greeter.dconf-defaults.bak" >> "/etc/gdm3/greeter.dconf-defaults"
        fi
        # Clean up after ourselves.
        rm "/etc/gdm3/greeter.dconf-defaults.bak"
        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
        DBDIR="/etc/dconf/db/gdm.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*banner-message-text\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)banner-message-text(\s*=)/#\1banner-message-text\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "'${login_banner_text}'")"
        if grep -q "^\\s*banner-message-text\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*banner-message-text\\s*=\\s*.*/banner-message-text=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-text=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # No need to use dconf update, since bash_dconf_settings does that already

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        DEBIAN_FRONTEND=noninteractive apt-get install -y "systemd-journal-remote"

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi



        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi



        DEBIAN_FRONTEND=noninteractive apt-get remove -y "avahi-daemon"

        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        SYSTEMCTL_EXEC='/usr/bin/systemctl'
        "$SYSTEMCTL_EXEC" stop 'avahi-daemon.service'
        "$SYSTEMCTL_EXEC" disable 'avahi-daemon.service'
        "$SYSTEMCTL_EXEC" mask 'avahi-daemon.service'
        # Disable socket activation if we have a unit file for it
        if "$SYSTEMCTL_EXEC" -q list-unit-files avahi-daemon.socket; then
            "$SYSTEMCTL_EXEC" stop 'avahi-daemon.socket'
            "$SYSTEMCTL_EXEC" mask 'avahi-daemon.socket'
        fi
        # The service may not be running because it has been started and failed,
        # so let's reset the state so OVAL checks pass.
        # Service should be 'inactive', not 'failed' after reboot though.
        "$SYSTEMCTL_EXEC" reset-failed 'avahi-daemon.service' || true

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        DEBIAN_FRONTEND=noninteractive apt-get remove -y "ldap-utils"
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "cups"
        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        SYSTEMCTL_EXEC='/usr/bin/systemctl'
        "$SYSTEMCTL_EXEC" stop 'cups.service'
        "$SYSTEMCTL_EXEC" disable 'cups.service'
        "$SYSTEMCTL_EXEC" mask 'cups.service'
        # Disable socket activation if we have a unit file for it
        if "$SYSTEMCTL_EXEC" -q list-unit-files cups.socket; then
            "$SYSTEMCTL_EXEC" stop 'cups.socket'
            "$SYSTEMCTL_EXEC" mask 'cups.socket'
        fi
        # The service may not be running because it has been started and failed,
        # so let's reset the state so OVAL checks pass.
        # Service should be 'inactive', not 'failed' after reboot though.
        "$SYSTEMCTL_EXEC" reset-failed 'cups.service' || true

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        DEBIAN_FRONTEND=noninteractive apt-get remove -y "xserver-xorg"

        sudo sysctl -w net.ipv4.conf.default.rp_filter=1
        echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf

        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        # Comment out any occurrences of net.ipv4.conf.default.rp_filter from /etc/sysctl.d/*.conf files

        for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf; do


          # skip systemd-sysctl symlink (/etc/sysctl.d/99-sysctl.conf -> /etc/sysctl.conf)
          if [[ "$(readlink -f "$f")" == "/etc/sysctl.conf" ]]; then continue; fi

          matching_list=$(grep -P '^(?!#).*[\s]*net.ipv4.conf.default.rp_filter.*$' $f | uniq )
          if ! test -z "$matching_list"; then
            while IFS= read -r entry; do
              escaped_entry=$(sed -e 's|/|\\/|g' <<< "$entry")
              # comment out "net.ipv4.conf.default.rp_filter" matches to preserve user data
              sed -i --follow-symlinks "s/^${escaped_entry}$/# &/g" $f
            done <<< "$matching_list"
          fi
        done
        sysctl_net_ipv4_conf_default_rp_filter_value='1'


        #
        # Set runtime for net.ipv4.conf.default.rp_filter
        #
        /sbin/sysctl -q -n -w net.ipv4.conf.default.rp_filter="$sysctl_net_ipv4_conf_default_rp_filter_value"

        #
        # If net.ipv4.conf.default.rp_filter present in /etc/sysctl.conf, change value to appropriate value
        #       else, add "net.ipv4.conf.default.rp_filter = value" to /etc/sysctl.conf
        #
        # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
        # Otherwise, regular sed command will do.
        sed_command=('sed' '-i')
        if test -L "/etc/sysctl.conf"; then
            sed_command+=('--follow-symlinks')
        fi

        # Strip any search characters in the key arg so that the key can be replaced without
        # adding any search characters to the config file.
        stripped_key=$(sed 's/[\^=\$,;+]*//g' <<< "^net.ipv4.conf.default.rp_filter")

        # shellcheck disable=SC2059
        printf -v formatted_output "%s = %s" "$stripped_key" "$sysctl_net_ipv4_conf_default_rp_filter_value"

        # If the key exists, change it. Otherwise, add it to the config_file.
        # We search for the key string followed by a word boundary (matched by \>),
        # so if we search for 'setting', 'setting2' won't match.
        if LC_ALL=C grep -q -m 1 -i -e "^net.ipv4.conf.default.rp_filter\\>" "/etc/sysctl.conf"; then
            escaped_formatted_output=$(sed -e 's|/|\\/|g' <<< "$formatted_output")
            "${sed_command[@]}" "s/^net.ipv4.conf.default.rp_filter\\>.*/$escaped_formatted_output/gi" "/etc/sysctl.conf"
        else
            if [[ -s "/etc/sysctl.conf" ]] && [[ -n "$(tail -c 1 -- "/etc/sysctl.conf" || true)" ]]; then
                LC_ALL=C sed -i --follow-symlinks '$a'\\ "/etc/sysctl.conf"
            fi

            printf '%s\n' "$formatted_output" >> "/etc/sysctl.conf"
        fi

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi
        fi
        DEBIAN_FRONTEND=noninteractive apt-get remove -y "apache2"

        # Remediation is applicable only in certain platforms
        if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

        var_sshd_set_maxstartups='10:30:60'


        if [ -e "/etc/ssh/sshd_config" ] ; then

            LC_ALL=C sed -i "/^\s*MaxStartups\s\+/Id" "/etc/ssh/sshd_config"
        else
            touch "/etc/ssh/sshd_config"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/ssh/sshd_config"

        cp "/etc/ssh/sshd_config" "/etc/ssh/sshd_config.bak"
        # Insert before the line matching the regex '^Match'.
        line_number="$(LC_ALL=C grep -n "^Match" "/etc/ssh/sshd_config.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '^Match', insert at
            # the end of the file.
            printf '%s\n' "MaxStartups $var_sshd_set_maxstartups" >> "/etc/ssh/sshd_config"
        else
            head -n "$(( line_number - 1 ))" "/etc/ssh/sshd_config.bak" > "/etc/ssh/sshd_config"
            printf '%s\n' "MaxStartups $var_sshd_set_maxstartups" >> "/etc/ssh/sshd_config"
            tail -n "+$(( line_number ))" "/etc/ssh/sshd_config.bak" >> "/etc/ssh/sshd_config"
        fi
        # Clean up after ourselves.
        rm "/etc/ssh/sshd_config.bak"

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        find / -xdev -type f -perm -002 -exec chmod o-w {} \;

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

        login_banner_text='^Authorized[\s\n]+uses[\s\n]+only\.[\s\n]+All[\s\n]+activity[\s\n]+may[\s\n]+be[\s\n]+monitored[\s\n]+and[\s\n]+reported\.$'


        # Multiple regexes transform the banner regex into a usable banner
        # 0 - Remove anchors around the banner text
        login_banner_text=$(echo "$login_banner_text" | sed 's/^\^\(.*\)\$$/\1/g')
        # 1 - Keep only the first banners if there are multiple
        #    (dod_banners contains the long and short banner)
        login_banner_text=$(echo "$login_banner_text" | sed 's/^(\(.*\.\)|.*)$/\1/g')
        # 2 - Add spaces ' '. (Transforms regex for "space or newline" into a " ")
        login_banner_text=$(echo "$login_banner_text" | sed 's/\[\\s\\n\]+/ /g')
        # 3 - Adds newline "tokens". (Transforms "(?:\[\\n\]+|(?:\\n)+)" into "(n)*")
        login_banner_text=$(echo "$login_banner_text" | sed 's/(?:\[\\n\]+|(?:\\\\n)+)/(n)*/g')
        # 4 - Remove any leftover backslash. (From any parethesis in the banner, for example).
        login_banner_text=$(echo "$login_banner_text" | sed 's/\\//g')
        # 5 - Removes the newline "token." (Transforms them into newline escape sequences "\n").
        #    ( Needs to be done after 4, otherwise the escapce sequence will become just "n".
        login_banner_text=$(echo "$login_banner_text" | sed 's/(n)\*/\\n/g')

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)

        # Will do both approach, since we plan to migrate to checks over dconf db. That way, future updates of the tool
        # will pass the check even if we decide to check only for the dconf db path.
        if [ -e "/etc/gdm3/greeter.dconf-defaults" ] ; then

            LC_ALL=C sed -i "/^\s*banner\-message\-text/Id" "/etc/gdm3/greeter.dconf-defaults"
        else
            touch "/etc/gdm3/greeter.dconf-defaults"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/gdm3/greeter.dconf-defaults"

        cp "/etc/gdm3/greeter.dconf-defaults" "/etc/gdm3/greeter.dconf-defaults.bak"
        # Insert after the line matching the regex '\[org/gnome/login-screen\]'
        line_number="$(LC_ALL=C grep -n "\[org/gnome/login-screen\]" "/etc/gdm3/greeter.dconf-defaults.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '\[org/gnome/login-screen\]', insert at
            # the end of the file.
            printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
        else
            head -n "$(( line_number ))" "/etc/gdm3/greeter.dconf-defaults.bak" > "/etc/gdm3/greeter.dconf-defaults"
            printf '%s\n' "banner-message-text='${login_banner_text}'" >> "/etc/gdm3/greeter.dconf-defaults"
            tail -n "+$(( line_number + 1 ))" "/etc/gdm3/greeter.dconf-defaults.bak" >> "/etc/gdm3/greeter.dconf-defaults"
        fi
        # Clean up after ourselves.
        rm "/etc/gdm3/greeter.dconf-defaults.bak"
        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
        DBDIR="/etc/dconf/db/gdm.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*banner-message-text\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)banner-message-text(\s*=)/#\1banner-message-text\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "'${login_banner_text}'")"
        if grep -q "^\\s*banner-message-text\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*banner-message-text\\s*=\\s*.*/banner-message-text=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-text=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # No need to use dconf update, since bash_dconf_settings does that already

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

        # Remediation is applicable only in certain platforms
        if dpkg-query --show --showformat='${db:Status-Status}\n' 'gdm3' 2>/dev/null | grep -q installed; then

        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/user

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:local" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:local\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        mkdir -p /etc/dconf/profile
        dconf_profile_path=/etc/dconf/profile/gdm

        [[ -s "${dconf_profile_path}" ]] || echo > "${dconf_profile_path}"

        if ! grep -Pzq "(?s)^\s*user-db:user.*\n\s*system-db:gdm" "${dconf_profile_path}"; then
            sed -i --follow-symlinks "1s/^/user-db:user\nsystem-db:gdm\n/" "${dconf_profile_path}"
        fi

        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/profile
        (umask 0022 && dconf update)
        # Duplicate the setting also in 'greeter.dconf-defaults' for consistency with
        # 'dconf_gnome_login_banner_text' and better alignment with STIG V1R1.
        if [ -e "/etc/gdm3/greeter.dconf-defaults" ] ; then

            LC_ALL=C sed -i "/^\s*banner\-message\-enable/Id" "/etc/gdm3/greeter.dconf-defaults"
        else
            touch "/etc/gdm3/greeter.dconf-defaults"
        fi
        # make sure file has newline at the end
        sed -i -e '$a\' "/etc/gdm3/greeter.dconf-defaults"

        cp "/etc/gdm3/greeter.dconf-defaults" "/etc/gdm3/greeter.dconf-defaults.bak"
        # Insert after the line matching the regex '\[org/gnome/login-screen\]'
        line_number="$(LC_ALL=C grep -n "\[org/gnome/login-screen\]" "/etc/gdm3/greeter.dconf-defaults.bak" | LC_ALL=C sed 's/:.*//g')"
        if [ -z "$line_number" ]; then
            # There was no match of '\[org/gnome/login-screen\]', insert at
            # the end of the file.
            printf '%s\n' "banner-message-enable=true" >> "/etc/gdm3/greeter.dconf-defaults"
        else
            head -n "$(( line_number ))" "/etc/gdm3/greeter.dconf-defaults.bak" > "/etc/gdm3/greeter.dconf-defaults"
            printf '%s\n' "banner-message-enable=true" >> "/etc/gdm3/greeter.dconf-defaults"
            tail -n "+$(( line_number + 1 ))" "/etc/gdm3/greeter.dconf-defaults.bak" >> "/etc/gdm3/greeter.dconf-defaults"
        fi
        # Clean up after ourselves.
        rm "/etc/gdm3/greeter.dconf-defaults.bak"


        # Check for setting in any of the DConf db directories
        # If files contain ibus or distro, ignore them.
        # The assignment assumes that individual filenames don't contain :
        readarray -t SETTINGSFILES < <(grep -r "\\[org/gnome/login-screen\\]" "/etc/dconf/db/" \
                                        | grep -v 'distro\|ibus\|gdm.d' | cut -d":" -f1)
        DCONFFILE="/etc/dconf/db/gdm.d/00-security-settings"
        DBDIR="/etc/dconf/db/gdm.d"

        mkdir -p "${DBDIR}"

        # Comment out the configurations in databases different from the target one
        if [ "${#SETTINGSFILES[@]}" -ne 0 ]
        then
            if grep -q "^\\s*banner-message-enable\\s*=" "${SETTINGSFILES[@]}"
            then

                sed -Ei "s/(^\s*)banner-message-enable(\s*=)/#\1banner-message-enable\2/g" "${SETTINGSFILES[@]}"
            fi
        fi


        [ ! -z "${DCONFFILE}" ] && echo "" >> "${DCONFFILE}"
        if ! grep -q "\\[org/gnome/login-screen\\]" "${DCONFFILE}"
        then
            printf '%s\n' "[org/gnome/login-screen]" >> ${DCONFFILE}
        fi

        escaped_value="$(sed -e 's/\\/\\\\/g' <<< "true")"
        if grep -q "^\\s*banner-message-enable\\s*=" "${DCONFFILE}"
        then
                sed -i "s/\\s*banner-message-enable\\s*=\\s*.*/banner-message-enable=${escaped_value}/g" "${DCONFFILE}"
            else
                sed -i "\\|\\[org/gnome/login-screen\\]|a\\banner-message-enable=${escaped_value}" "${DCONFFILE}"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)
        # Check for setting in any of the DConf db directories
        LOCKFILES=$(grep -r "^/org/gnome/login-screen/banner-message-enable$" "/etc/dconf/db/" \
                    | grep -v 'distro\|ibus\|gdm.d' | grep ":" | cut -d":" -f1)
        LOCKSFOLDER="/etc/dconf/db/gdm.d/locks"

        mkdir -p "${LOCKSFOLDER}"

        # Comment out the configurations in databases different from the target one
        if [[ ! -z "${LOCKFILES}" ]]
        then
            sed -i -E "s|^/org/gnome/login-screen/banner-message-enable$|#&|" "${LOCKFILES[@]}"
        fi

        if ! grep -qr "^/org/gnome/login-screen/banner-message-enable$" /etc/dconf/db/gdm.d/
        then
            echo "/org/gnome/login-screen/banner-message-enable" >> "/etc/dconf/db/gdm.d/locks/00-security-settings-lock"
        fi
        # Make sure permissions allow regular users to read dconf settings.
        # Also define the umask to avoid `dconf update` changing permissions.
        chmod -R u=rwX,go=rX /etc/dconf/db
        (umask 0022 && dconf update)

        else
            >&2 echo 'Remediation is not applicable, nothing was done'
        fi

