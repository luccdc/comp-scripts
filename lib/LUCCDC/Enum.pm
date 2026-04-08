package LUCCDC::Enum;

use base qw(Exporter);

our @EXPORT      = qw(list_sus_files);
our @EXPORT_OK   = qw(list_sus_files);
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
        "Writable root owned" => [ split(/\n/xms, `find /etc -type f -perm -o+w | xargs ls -ald `) ],
        "SET\{U,G\}ID Files"  => [ split(/\n/xms, `find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | xargs ls -ald`) ],
        "Unmanaged Files"     => list_unmanaged_files(),
        "Managed Files" => {
            "Missing Files" => $missing,
            "Changed Files" => $changed,
        }
    };
}


1;
