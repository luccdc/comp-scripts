package LUCCDC::Enum;

use base qw(Exporter);

our @EXPORT      = qw(list_sus_files list_systemd);
our @EXPORT_OK   = qw(list_sus_files list_systemd);
our %EXPORT_TAGS = (
    ALL => [ @EXPORT, @EXPORT_OK ],
);


sub list_managed_files {
    my @lines=split(/\n/xms, `dpkg -V`);

    my @missing = grep {/^missing \s /xms} @lines;
    my @changed = grep {/^\?{2} 5 \?{6} /xms} @lines;

    return \@missing, \@changed;
}

sub list_unmanaged_files {

    my @excluded_dirs = (
        "/home",
        "/sys",
        "/dev",
        "/proc",
        "/tmp",
        "/var/mail",
        "/var/spool/mail",
        "/var/lib/shells.state",
        "/var/lib/apt/extended_states",
        "/var/lib/systemd/deb-systemd-helper-enabled",
        "/var/lib/apt/lists",
        "/var/lib/dpkg",
        "/var/lib/pam/account",
        "/var/lib/pam/auth",
        "/var/lib/pam/password",
        "/var/lib/pam/seen",
        "/var/lib/pam/session",
        "/var/lib/pam/session-noninteractive",
        "/var/cache",
        "/var/tmp",
        "/var/log",
        "/var/opt",
        "/run",
        "/media",
        "/mnt",
        "/etc/profile",
        "/etc/group",
        "/etc/group-",
        "/etc/hostname",
        "/usr/local",
        "/usr/share/man",
        "/etc/alternatives",
        "/etc/hosts",
        "/etc/shadow",
        "/etc/shadow-",
        "/etc/passwd",
        "/etc/passwd-",
        "/etc/gshadow",
        "/etc/gshadow-",
        "/etc/shells",
        "/etc/fstab",
        "/etc/mtab",
        "/etc/networks",
        "/etc/environment",
        "/etc/subuid",
        "/etc/subuid-",
        "/etc/subgid",
        "/etc/subgid-",
        "/etc/machine-id",
        "/etc/nsswitch.conf",
        "/etc/ld.so.cache",
        "/etc/resolv.conf",
        "/etc/systemd/system/timers.target.wants",
        "/etc/systemd/system/multi-user.target.wants",
        "/etc/pam.d/common-account",
        "/etc/pam.d/common-auth",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-password",
        "/etc/pam.d/common-session-noninteractive",
        "/root/.profile",
        "/root/.bashrc",
        "/boot",
        "/etc/ssl/certs",
        "/usr/share/mime",
        "/usr/lib/python2.7",
        "/usr/lib/python3",
        "/usr/lib/python3.4",
        "/etc/rc0.d",
        "/etc/rc1.d",
        "/etc/rc2.d",
        "/etc/rc3.d",
        "/etc/rc4.d",
        "/etc/rc5.d",
        "/etc/rc6.d",
        "/etc/rcS.d",
        "/var/lib/cloud",

    );

    my $find_paths = "-path " . join(" -o -path ", @excluded_dirs);

    my @all_paths = split(/\n/, `find / \\( $find_paths \\) -prune -o -print | sort`);
    my @managed_paths = split(/\n/, `cat /var/lib/dpkg/info/*.list | sort`);

    my %paths_hash = map {$_ => 1} @managed_paths;

    my @unmanaged_paths = grep { ! $paths_hash{$_} } @all_paths;
    return \@unmanaged_paths;
}

sub list_sus_files {

    my ($missing, $changed) = list_managed_files();

    return {
        "Writable root owned" => [ split(/\n/xms, `find /etc /var /bin /sbin /usr -type f -perm -o+w | xargs ls -ald `) ],
        "SET\{U,G\}ID Files"  => [ split(/\n/xms, `find /etc /var /bin /sbin /usr -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | xargs ls -ald`) ],
        "Unmanaged Files"     => list_unmanaged_files(),
        "Managed Files" => {
            "Missing Files" => $missing,
            "Changed Files" => $changed,
        }
    };
}


sub extract_execstart_binaries {
    my %seen;
    my @dirs = qw(
        /etc/systemd/system
        /run/systemd/system
        /usr/lib/systemd/system
        /lib/systemd/system
    );

    # Get all ExecStart= lines using grep (fast and reliable)
    my @execstarts = split(/\n/, `grep -or 'ExecStart=.*' @dirs 2>/dev/null`);

    my @results;

    # Suspicious binaries (add more as needed)
    my %suspicious = map { $_ => 1 } qw(
        nc netcat ncat openssl socat curl wget nft iptables ip6tables
        python python3 perl ruby node php busybox sh dash zsh
        telnet sshpass expect base64 xxd hexdump
    );

    for my $line (@execstarts) {
        next unless $line =~ m{^(.+?\.service):(.+)$};

        my $service = $1;
        my $command = $2;

        # Extract binary for suspicious check
        my $binary = ($command =~ m{^\s*ExecStart\s*=\s*["']?([^\s"']+)}) ? $1 : '';

        # Color suspicious binaries bright yellow
        if ($binary && ($suspicious{$binary} || $binary =~ m{/(nc|netcat|ncat|openssl|socat|nft|curl|wget)$})) {
            $command =~ s{($binary)}{\e[1;33m$1\e[0m}g;
        }

        # Push with nice spacing between service and command
        push @results, sprintf("%-48s →  %s", $service, $command);
    }

    my @sorted = sort @results;
    return \@sorted;
}


sub list_systemd {
    return {
        "Systemd binaries" => extract_execstart_binaries(),
    };
}


1;
