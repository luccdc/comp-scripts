package LUCCDC::Enum;

use base qw(Exporter);

our @EXPORT      = qw();
our @EXPORT_OK   = qw(enum_packages enum_files);
our %EXPORT_TAGS = (
    ALL => [ @EXPORT, @EXPORT_OK ],
);


sub enum_packages {
    my @lines=split(/\n/xms, `dpkg -V`);

    my $missing = grep {/^missing \s /xms} @lines;
    #    my $altered = grep {jfi}

}

sub enum_files {

    my @excluded_dirs = (
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

    my @path_packages = split(/\n/, `find / \\( $find_paths \\) -prune -o -print | xargs dpkg -S`);
    my @invalid_paths = grep { /no path found matching pattern/xms } @path_packages;

    print join("\n", @invalid_paths);

}

1;
